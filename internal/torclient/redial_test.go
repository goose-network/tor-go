package torclient

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goose-network/tor-go/internal/directory"
	"github.com/goose-network/tor-go/internal/link"
	"github.com/goose-network/tor-go/internal/testharness"
)

// TestRedialGuardKeepsFreshLink is the regression for the redial-storm bug: a
// losing redialer holding a STALE observed link must not Close the fresh link a
// concurrent winner already installed. redialGuard's identity check
// (cur != observed && cur != nil) returns early, leaving c.link intact and the
// healthy link alive. Without it, every concurrent redialer whose swap landed
// after a winner would tear down the fresh link, cascading into a redial storm
// that severs all in-flight streams.
func TestRedialGuardKeepsFreshLink(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.Relays[0]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := guard.IdentityDigest()
	fresh, err := link.Dial(ctx, guard.Addr(), id[:])
	if err != nil {
		t.Fatalf("dial fresh link: %v", err)
	}
	defer fresh.Close()
	stale, err := link.Dial(ctx, guard.Addr(), id[:])
	if err != nil {
		t.Fatalf("dial stale link: %v", err)
	}
	defer stale.Close()

	// The client already renewed to fresh; a redialer still holding stale fires.
	c := &Client{link: fresh}
	c.redialGuard(ctx, stale)

	if c.link != fresh {
		t.Fatal("redialGuard clobbered the fresh link with a stale observed pointer")
	}
	if !fresh.IsAlive() {
		t.Fatal("redialGuard closed the fresh healthy link; identity check failed (redial storm)")
	}
}

// TestNoteLinkStrikeConcurrentBelowThreshold verifies the CAS strike loop counts
// each concurrent link-suspect failure exactly once (no lost increments) and
// does not cross the redial threshold prematurely. threshold-1 concurrent
// strikes must leave the counter at exactly threshold-1, with no background
// redial spawned (which would dial the guard). The race detector exercises the
// CAS loop; the threshold-cross detach itself is verified by the live sweep.
func TestNoteLinkStrikeConcurrentBelowThreshold(t *testing.T) {
	c := &Client{}
	n := linkStrikeThreshold - 1
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.noteLinkStrike(context.Background(), nil)
		}()
	}
	wg.Wait()
	if got := c.linkStrikes.Load(); got != int32(n) {
		t.Fatalf("linkStrikes = %d after %d concurrent strikes, want %d (CAS lost increments or premature cross)", got, n, n)
	}
}

// TestDialGuardDoesNotInstallAfterClose is the regression for the dial-after-close
// zombie. Fix H's detached strike-redial runs on context.WithoutCancel, so a guard
// dial can complete AFTER Run/Serve shut the client down. dialGuard must re-check
// c.closed under c.mu before installing c.link and CLOSE the freshly dialed link if
// the client closed; otherwise a closed, reference-dropped client owns an immortal
// live guard link (+ readLoop goroutine + upstream-route tunnel) nothing ever closes,
// accumulating across provider restarts. Shutdown holds c.mu to set closed, so the
// re-check is mutually exclusive with it.
func TestDialGuardDoesNotInstallAfterClose(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	e := h.AllEntries()[0]
	r := &directory.Router{RouterIdentity: link.RouterIdentity{
		Nickname: e.Nickname,
		Address:  e.Address,
		IDDigest: e.IDDigest,
		OnionKey: e.OnionKey,
	}}
	c := &Client{
		cfg:    &Config{LinkDialTimeout: 5 * time.Second},
		closed: true, // client already shut down while the dial is in flight
	}
	err = c.dialGuard(context.Background(), r, "")
	// Assert the SPECIFIC install-time rejection, not merely any error: a dial
	// failure (unreachable guard, identity mismatch) returns "connect to guard …"
	// and would let this test pass without ever exercising the closed re-check.
	// Matching the closed-during-dial message proves the dial SUCCEEDED and the
	// install-site c.closed guard fired.
	if err == nil || !strings.Contains(err.Error(), "client closed during guard dial") {
		t.Fatalf("dialGuard on closed client: got %v, want the install-time closed rejection (dial-after-close zombie)", err)
	}
	if c.link != nil {
		t.Fatal("dialGuard set c.link on a closed client; the fresh link must be closed, not installed")
	}
	if c.guard != nil {
		t.Fatal("dialGuard set c.guard on a closed client")
	}
}

// TestDeafUnderLoadGate is the regression for the keepAlive idle-resume false-kill
// (Defect Y). keepAliveLoop's gated-silence check measures inbound silence from the
// last received cell, INCLUDING the idle period before a fresh write, so a healthy
// link idle > silenceThreshold that resumes with a single CREATE2 looked "silent
// under load" and was redialed mid-handshake — failing the resuming probe. The fix
// adds writesSinceRead >= 2 (the same protection the readLoop gate has). This pins
// the predicate: a single outstanding handshake cell after a long idle is NOT deaf,
// while sustained unanswered outbound IS, and trailing teardown writes that have
// aged past recentWriteWindow are spared.
func TestDeafUnderLoadGate(t *testing.T) {
	const st = 60 * time.Second // silenceThreshold
	const rw = 60 * time.Second // recentWriteWindow
	cases := []struct {
		name             string
		silent, writeAge time.Duration
		writes           int64
		want             bool
	}{
		{"idle-resume single CREATE2 (the false-kill)", 80 * time.Second, 1 * time.Second, 1, false},
		{"idle-resume single trailing RELAY_END", 80 * time.Second, 1 * time.Second, 1, false},
		{"deaf under sustained load", 80 * time.Second, 1 * time.Second, 3, true},
		{"two unanswered cells, recent write, long silence", 80 * time.Second, 1 * time.Second, 2, true},
		{"pure idle, no real writes", 80 * time.Second, 80 * time.Second, 0, false},
		{"trailing END+DESTROY aged past window", 80 * time.Second, 80 * time.Second, 2, false},
		{"silence below threshold", 30 * time.Second, 1 * time.Second, 3, false},
		{"write older than recent window", 80 * time.Second, 70 * time.Second, 3, false},
		{"fresh link, no silence", 1 * time.Second, 1 * time.Second, 0, false},
	}
	for _, c := range cases {
		if got := deafUnderLoad(c.silent, c.writeAge, c.writes, st, rw); got != c.want {
			t.Errorf("%s: deafUnderLoad(silent=%s writeAge=%s writes=%d) = %v, want %v",
				c.name, c.silent, c.writeAge, c.writes, got, c.want)
		}
	}
}
