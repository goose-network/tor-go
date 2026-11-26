package testharness_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/goose-network/tor-go/internal/circuit"
	"github.com/goose-network/tor-go/internal/link"
	"github.com/goose-network/tor-go/internal/testharness"
	"github.com/goose-network/tor-go/internal/torcell"
)

// TestLinkIdleSilenceKeepsHealthyIdleLink verifies the silence gate on the
// rolling read deadline: a link that receives no inbound cell but has sent NO
// real (non-padding) circuit cells recently is a healthy IDLE link, not a deaf
// one. Tor does not negotiate channel padding here and relays drop unsolicited
// PADDING without reply, so inbound silence alone is ambiguous — reaping on it
// would sever healthy idle streams every idleTimeout. readLoop must refresh the
// deadline and keep the link alive across many idle windows.
func TestLinkIdleSilenceKeepsHealthyIdleLink(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.Relays[0]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := guard.IdentityDigest()
	l, err := link.Dial(ctx, guard.Addr(), id[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()
	if !l.IsAlive() {
		t.Fatal("freshly dialed link should be alive")
	}

	// Arm a short idle deadline but send no real cells. The relay answers
	// nothing while idle, so ReadAny times out repeatedly; the gate must keep
	// the link rather than treat the silence as death.
	l.SetIdleTimeout(150 * time.Millisecond)
	// Force an inbound cell AFTER SetIdleTimeout so readLoop deterministically
	// re-arms the short idle. SetIdleTimeout only stores; readLoop's first
	// iteration may already have armed the 120s default before the store lands
	// (a startup race), in which case the deadline never fires within the test
	// and the keep-gate passes vacuously. CREATED_FAST zeroes the write counter
	// and re-arms, so the idle silence below genuinely trips the gate.
	circ, err := circuit.NewOneHopFast(ctx, l)
	if err != nil {
		t.Fatalf("NewOneHopFast: %v", err)
	}
	defer circ.Close()
	time.Sleep(700 * time.Millisecond) // ~4-5 idle windows
	if !l.IsAlive() {
		t.Fatal("healthy idle link was reaped by the read deadline; the silence gate failed")
	}
}

// TestLinkIdleDeadlineDetectsDeafLinkUnderLoad verifies the rolling read
// deadline reaps a deaf-but-unclosed tunnel UNDER LOAD: real circuit cells were
// recently sent but nothing comes back (an upstream proxy that black-holes the
// connection without FIN/RST). Previously readLoop blocked forever and IsAlive
// stayed true, so the client never redialed and every probe burned its full
// budget. The mock relay drops PADDING without reply, so sending it via Send
// (which tracks lastWrite, unlike SendPadding) stands in for real outbound on a
// deaf tunnel: recent write + inbound silence trips the deadline and kills it.
func TestLinkIdleDeadlineDetectsDeafLinkUnderLoad(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.Relays[0]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := guard.IdentityDigest()
	l, err := link.Dial(ctx, guard.Addr(), id[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()
	if !l.IsAlive() {
		t.Fatal("freshly dialed link should be alive")
	}

	l.SetIdleTimeout(200 * time.Millisecond)
	// Force an inbound cell AFTER SetIdleTimeout so readLoop deterministically
	// re-arms the short idle. SetIdleTimeout only stores; readLoop's first
	// iteration can arm the 120s default first (a startup race). Under parallel
	// -race suite load that race leaves the first-byte read blocked on the 120s
	// default for the whole 3s budget — no inbound ever arrives on a deaf link —
	// so the deadline never fires and the link is wrongly still alive. CREATED_FAST
	// re-arms 200ms and zeroes the write counter; the unanswered ticker below then
	// drives the sustained-load kill deterministically.
	circ, err := circuit.NewOneHopFast(ctx, l)
	if err != nil {
		t.Fatalf("NewOneHopFast: %v", err)
	}
	defer circ.Close()
	// Keep lastWrite fresh with tracked cells the relay never answers, so every
	// read timeout sees recent outbound (deaf under load) rather than idle.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := l.Send(&torcell.Cell{Command: torcell.CellPadding}); err != nil {
					return
				}
			}
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && l.IsAlive() {
		time.Sleep(20 * time.Millisecond)
	}
	if l.IsAlive() {
		t.Fatal("link still alive after the idle deadline elapsed under load; deaf-link detection failed")
	}
	// Wait returns the read error that ended the loop (a deadline timeout).
	if err := l.Wait(); err == nil {
		t.Fatal("Wait returned nil, want the read timeout error that killed the link")
	}
}

// TestStreamReadUnblocksOnLinkDeath verifies link-death propagation into the
// data phase: when the guard link dies, circuit.readLoop must tear down the
// streams so a pending Stream.Read returns promptly instead of hanging forever
// (the curl-empty-body / hung-probe failure mode). Nothing closes the circuit's
// inbound channel on link death, so without the readLoop's link.Done() case the
// reader would block indefinitely.
func TestStreamReadUnblocksOnLinkDeath(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.Relays[0]

	// An origin that accepts the exit's connection but sends nothing, so the
	// client's Stream.Read blocks waiting for DATA.
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer originLn.Close()
	hold := make(chan struct{})
	defer close(hold)
	go func() {
		c, err := originLn.Accept()
		if err != nil {
			return
		}
		<-hold
		_ = c.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := guard.IdentityDigest()
	l, err := link.Dial(ctx, guard.Addr(), id[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()
	circ, err := circuit.NewOneHopFast(ctx, l)
	if err != nil {
		t.Fatalf("NewOneHopFast: %v", err)
	}
	defer circ.Close()
	stream, err := circ.OpenStream(ctx, originLn.Addr().String())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	// Start a Read that blocks (the origin sends nothing).
	errCh := make(chan error, 1)
	go func() {
		_, rerr := stream.Read()
		errCh <- rerr
	}()
	// Let the reader settle into its blocking receive on the stream channel.
	time.Sleep(200 * time.Millisecond)

	// Kill the guard link. The pending Read must unblock promptly.
	l.Close()
	select {
	case rerr := <-errCh:
		if rerr == nil {
			t.Fatal("Stream.Read returned nil error after link death, want an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stream.Read still blocked 3s after guard link death; link-death propagation failed")
	}
}

// TestCircuitWaiterReturnsOnTeardown is the regression for two waiter defects.
// (1) The nil-cell deref that crashed the engine on guard-link death:
// closeAllStreams does close(s.in), a closed-channel receive yields a nil rc, and
// dereferencing rc.Header.Command panicked — the ok-check fixes that. (2) The
// ok-check must DISTINGUISH link death from an ordinary circuit teardown with the
// link still ALIVE (relay DESTROY/TRUNCATED, deliver-window overrun, Circuit.Close):
// link death surfaces ErrLinkDied (strike/redial the guard), a live-link teardown
// surfaces ErrCircuitClosed (retry a fresh path, NO strike). Conflating them let a
// bad middle/exit accrue guard strikes and redial a HEALTHY guard, severing every
// unrelated in-flight stream — the exact harm fix B exists to prevent.
//
// BeginDir and Resolve are used because the mock relay's dispatchForward has no
// case for BEGIN_DIR/RESOLVE: it never replies, so the waiter blocks on <-s.in
// deterministically. Circuit.Close closes s.in WITHOUT closing the link, so the
// closed-channel receive is the only ready case (ErrCircuitClosed); link.Close
// exits the read loop and fires link.Done() (ErrLinkDied).
func TestCircuitWaiterReturnsOnTeardown(t *testing.T) {
	calls := []struct {
		name string
		call func(ctx context.Context, c *circuit.Circuit) error
	}{
		{"Resolve", func(ctx context.Context, c *circuit.Circuit) error {
			_, err := c.Resolve(ctx, "example.com")
			return err
		}},
		{"BeginDir", func(ctx context.Context, c *circuit.Circuit) error {
			_, err := c.BeginDir(ctx)
			return err
		}},
	}
	modes := []struct {
		name    string
		kill    func(c *circuit.Circuit, l *link.Link)
		wantErr error
	}{
		{"circuit-close-live-link", func(c *circuit.Circuit, l *link.Link) { c.Close() }, circuit.ErrCircuitClosed},
		{"link-death", func(c *circuit.Circuit, l *link.Link) { l.Close() }, circuit.ErrLinkDied},
	}
	for _, tc := range calls {
		for _, m := range modes {
			t.Run(tc.name+"/"+m.name, func(t *testing.T) {
				h, err := testharness.NewHarness(1)
				if err != nil {
					t.Fatalf("NewHarness: %v", err)
				}
				defer h.Close()
				guard := h.Relays[0]
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				id := guard.IdentityDigest()
				l, err := link.Dial(ctx, guard.Addr(), id[:])
				if err != nil {
					t.Fatalf("link.Dial: %v", err)
				}
				defer l.Close()
				circ, err := circuit.NewOneHopFast(ctx, l)
				if err != nil {
					t.Fatalf("NewOneHopFast: %v", err)
				}
				defer circ.Close()
				type result struct {
					err      error
					panicked bool
				}
				resCh := make(chan result, 1)
				go func() {
					defer func() {
						if r := recover(); r != nil {
							resCh <- result{panicked: true}
						}
					}()
					resCh <- result{err: tc.call(ctx, circ)}
				}()
				time.Sleep(200 * time.Millisecond)
				m.kill(circ, l)
				select {
				case r := <-resCh:
					if r.panicked {
						t.Fatal("waiter panicked on closed s.in (nil-cell deref); the ok-check fix is missing")
					}
					if !errors.Is(r.err, m.wantErr) {
						t.Fatalf("waiter returned %v, want %v", r.err, m.wantErr)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("waiter still blocked 3s after teardown; closeAllStreams did not unblock it")
				}
			})
		}
	}
}

// TestLinkSingleWriteThenSilenceKeepsLink is the regression for the false-kill: a
// SINGLE real outbound cell followed by inbound silence (a slow origin's reply
// still pending, or a trailing RELAY_END/SENDME after the last DATA) shares the
// "recent write + silence" signature of a deaf tunnel but is NOT deaf. The kill
// gate requires SUSTAINED unanswered outbound (>= 2 real cells since the last
// inbound), so one outstanding write must keep the link across many idle windows.
// TestLinkIdleDeadlineDetectsDeafLinkUnderLoad covers the sustained-write kill.
func TestLinkSingleWriteThenSilenceKeepsLink(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.Relays[0]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := guard.IdentityDigest()
	l, err := link.Dial(ctx, guard.Addr(), id[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()
	l.SetIdleTimeout(150 * time.Millisecond)
	// Force an inbound cell AFTER SetIdleTimeout so readLoop deterministically
	// re-arms the short idle (it only stores; the first iteration may arm the
	// 120s default first). CREATED_FAST zeroes the counter, then the single Send
	// below leaves exactly one outstanding write.
	circ, err := circuit.NewOneHopFast(ctx, l)
	if err != nil {
		t.Fatalf("NewOneHopFast: %v", err)
	}
	defer circ.Close()
	// One real cell the relay never answers (writesSinceRead becomes 1). The mock
	// drops PADDING without reply, so Send stands in for a single outstanding write.
	if err := l.Send(&torcell.Cell{Command: torcell.CellPadding}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	time.Sleep(700 * time.Millisecond) // ~4-5 idle windows
	if !l.IsAlive() {
		t.Fatal("a single outstanding write + silence reaped a healthy link; the sustained-load gate failed")
	}
}

// TestLinkTwoTrailingWritesAfterInboundKeepsLink is the regression for Defect X:
// the rolling-deadline gate's recency disjunct used ">= idle", which is dead code —
// the deadline fires idle after the last inbound and every counted write is
// post-inbound, so Since(LastWrite) < idle ALWAYS holds. The effective rule became
// ">= 2 unanswered cells + idle silence => kill", which reaps the ubiquitous
// END+DESTROY teardown pair (Stream.Close sends RELAY_END, Circuit.Close sends
// DESTROY; real relays answer neither) on every quiet link ~idle after each probe.
// The fix uses idle/2 so trailing writes sent right after the last inbound age past
// the window by the fire instant and are kept.
//
// A one-hop fast circuit provides a deterministic inbound cell (CREATED_FAST) AFTER
// SetIdleTimeout, which re-arms the read deadline to the short idle and zeroes
// writesSinceRead. Two trailing tracked cells the relay never answers then stand in
// for END+DESTROY. Across several idle windows the healthy link must stay alive.
func TestLinkTwoTrailingWritesAfterInboundKeepsLink(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.Relays[0]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := guard.IdentityDigest()
	l, err := link.Dial(ctx, guard.Addr(), id[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()
	l.SetIdleTimeout(300 * time.Millisecond)
	// Force an inbound cell after SetIdleTimeout: CREATED_FAST resets writesSinceRead
	// to 0 and makes readLoop re-arm the deadline to the short idle deterministically.
	circ, err := circuit.NewOneHopFast(ctx, l)
	if err != nil {
		t.Fatalf("NewOneHopFast: %v", err)
	}
	defer circ.Close()
	// Let the inbound settle, then send the trailing writes a beat later so they
	// land clearly INSIDE the idle window (write age at the fire instant = idle-60ms,
	// strictly between idle/2 and idle). With delta≈0 the old ">= idle" gate is
	// borderline (Since(LastWrite)≈idle) and races; a 60ms gap makes the old gate
	// reliably KILL (idle-60ms < idle) while the fixed idle/2 gate reliably KEEPS
	// (idle-60ms >= idle/2). This is the END+DESTROY-after-last-DATA signature.
	time.Sleep(60 * time.Millisecond)
	// Two trailing real cells the relay never answers (writesSinceRead becomes 2).
	// PADDING on circID 0 is dropped without reply, like a real relay.
	for i := 0; i < 2; i++ {
		if err := l.Send(&torcell.Cell{Command: torcell.CellPadding}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	time.Sleep(1200 * time.Millisecond) // ~4 idle windows
	if !l.IsAlive() {
		t.Fatal("two trailing unanswered writes after an inbound cell reaped a healthy link; the idle/2 recency gate failed (END+DESTROY teardown false-kill)")
	}
}
