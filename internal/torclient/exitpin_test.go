package torclient

import (
	"testing"

	"github.com/goose-network/tor-go/internal/directory"
)

// TestExitInfosListsExitFlaggedRelays covers the per-exit outbound source:
// ExitInfos must report exactly the relays with the Exit flag and an onion
// key, keyed by the hex identity digest RouterByIDDigest resolves back.
func TestExitInfosListsExitFlaggedRelays(t *testing.T) {
	dir := directory.MockDirectory()
	// The mock set has one Exit-flagged relay (mockexit) and two without the
	// flag (mockguard, mockmiddle).
	c, err := New(t.Context(), &Config{Directory: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	infos := c.ExitInfos()
	if len(infos) != 1 {
		t.Fatalf("ExitInfos = %d entries, want 1 (only mockexit carries the Exit flag): %+v", len(infos), infos)
	}
	info := infos[0]
	if info.Nickname != "mockexit" || !info.IsExit {
		t.Fatalf("ExitInfos[0] = %+v, want nickname mockexit flagged as exit", info)
	}
	if info.Address == "" {
		t.Fatalf("ExitInfos[0].Address empty; the exit's OR address must be reported for the outbound display")
	}

	// The digest must round-trip through RouterByIDDigest.
	r, err := c.RouterByIDDigest(info.IDDigest)
	if err != nil {
		t.Fatalf("RouterByIDDigest(%q): %v", info.IDDigest, err)
	}
	if r == nil || r.Nickname != "mockexit" {
		t.Fatalf("RouterByIDDigest(%q) = %+v, want mockexit back", info.IDDigest, r)
	}

	// A relay without the Exit flag resolves (it is still in the directory)
	// even though ExitInfos never lists it.
	mid := directory.FindByNickname(dir, "mockmiddle")
	r, err = c.RouterByIDDigest(hexIDDigest(mid))
	if err != nil {
		t.Fatalf("RouterByIDDigest(middle): %v", err)
	}
	if r == nil || r.Nickname != "mockmiddle" {
		t.Fatalf("RouterByIDDigest(middle) = %+v, want mockmiddle (lookup works regardless of flags)", r)
	}
}

// TestRouterByIDDigestRejectsBadInput pins the error contract for the dial
// path: malformed digests fail with an error (visible in dial errors), not a
// silent nil lookup that would read as "left the directory".
func TestRouterByIDDigestRejectsBadInput(t *testing.T) {
	c, err := New(t.Context(), &Config{Directory: directory.MockDirectory()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, bad := range []string{"", "zz", "not-a-digest", "0123456789abcdef0123456789abcdef0123456789"} {
		if r, err := c.RouterByIDDigest(bad); err == nil {
			t.Errorf("RouterByIDDigest(%q) = (%v, nil), want an input error", bad, r)
		}
	}
}

// TestBuildPathPinsExit verifies the per-exit circuit form: with a pinned
// digest, the last hop is exactly that relay; unpinned dials keep the random
// exit selection. buildPath is exercised through the client with no guard
// link required (path selection never dials).
func TestBuildPathPinsExit(t *testing.T) {
	dir := directory.MockDirectory()
	c, err := New(t.Context(), &Config{Directory: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exit := directory.FindByNickname(dir, "mockexit")

	c.mu.Lock()
	c.guard = directory.FindByNickname(dir, "mockguard")
	c.mu.Unlock()

	path, err := c.buildPath(hexIDDigest(exit))
	if err != nil {
		t.Fatalf("buildPath(pinned): %v", err)
	}
	if got := path[len(path)-1]; got.IDDigest != exit.IDDigest {
		t.Fatalf("pinned path exit = %x, want %x (mockexit)", got.IDDigest, exit.IDDigest)
	}
	if got := path[0]; got.IDDigest != c.guard.IDDigest {
		t.Fatalf("pinned path guard = %x, want the configured guard", got.IDDigest)
	}

	// Unpinned: last hop still Exit-flagged, but not required to be a
	// specific relay; in the mock set, SelectExit can only pick mockexit too.
	path, err = c.buildPath("")
	if err != nil {
		t.Fatalf("buildPath(unpinned): %v", err)
	}
	if got := path[len(path)-1]; got.IDDigest != exit.IDDigest {
		t.Fatalf("unpinned path exit = %x, want mockexit (the only Exit-flagged relay)", got.IDDigest)
	}

	// A relay missing from the directory (fresh digest) fails cleanly.
	if _, err := c.buildPath("ffffffffffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("buildPath(unknown digest) succeeded; want a not-in-directory error")
	}
}
