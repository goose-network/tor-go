package directory

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestParseConsensus(t *testing.T) {
	// A tiny microconsensus with two relays. The identity field on an "r"
	// line is the base64 of a 20-byte SHA-1 digest, so it must decode to
	// exactly 20 bytes (28 base64 chars incl. padding).
	text := []byte(`r mockguard ERERERERERERERERERERERERERE= EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE 2026-01-01 00:00:00 1.2.3.4 9001 9030
s Fast Guard Stable Valid
m H4sIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

r mockexit IiIiIiIiIiIiIiIiIiIiIiIiIiI= FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 2026-01-01 00:00:00 5.6.7.8 9001 9030
s Exit Fast Stable Valid
m H4sIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
`)
	routers, err := ParseConsensus(text)
	if err != nil {
		t.Fatalf("ParseConsensus: %v", err)
	}
	if len(routers) != 2 {
		t.Fatalf("got %d routers, want 2", len(routers))
	}
	// Find the guard by nickname.
	var guard *Router
	for _, r := range routers {
		if r.Nickname == "mockguard" {
			guard = r
		}
	}
	if guard == nil {
		t.Fatal("mockguard not found")
	}
	if guard.Address != "1.2.3.4:9001" {
		t.Fatalf("guard address = %q, want 1.2.3.4:9001", guard.Address)
	}
	if !hasFlag(guard, "Guard") {
		t.Fatal("guard missing Guard flag")
	}
	// The identity digest should be the base64-decoded 20 bytes.
	if (guard.IDDigest == [20]byte{}) {
		t.Fatal("guard IDDigest is zero")
	}
}

func TestParseMicrodescriptors(t *testing.T) {
	// Build a router, then a microdesc whose ntor-onion-key we can verify.
	// The microdesc digest (set from the consensus "m" line) must equal the
	// SHA-256 of the microdescriptor body, so we compute it here and set it
	// on the router before parsing.
	routers := make(map[string]*Router)
	r := &Router{Nickname: "mockguard"}
	copy(r.IDDigest[:], []byte("12345678901234567890"))
	routers[encodeID(r.IDDigest)] = r

	// Encode a 32-byte ntor key in base64.
	ntor := make([]byte, 32)
	for i := range ntor {
		ntor[i] = 0x42
	}
	ntorB64 := base64.StdEncoding.EncodeToString(ntor)
	microdesc := []byte("onion-key\n" +
		"ntor-onion-key " + ntorB64 + "\n" +
		"w Bandwidth=50000\n")
	// The microdesc digest is the sha256 of the body (with trailing newline).
	r.MicrodescDigest = sha256.Sum256(microdesc)

	if err := ParseMicrodescriptors(microdesc, routers); err != nil {
		t.Fatalf("ParseMicrodescriptors: %v", err)
	}
	got := routers[encodeID(r.IDDigest)]
	if got.OnionKey != ([32]byte(ntor)) {
		t.Fatalf("onion key = %x, want %x", got.OnionKey, ntor)
	}
	if got.Bandwidth != 50000 {
		t.Fatalf("bandwidth = %d, want 50000", got.Bandwidth)
	}
}

func TestSelectGuardExitMiddle(t *testing.T) {
	routers := MockDirectory()
	g, err := SelectGuard(routers)
	if err != nil {
		t.Fatalf("SelectGuard: %v", err)
	}
	if !hasFlag(g, "Guard") {
		t.Fatal("selected guard lacks Guard flag")
	}
	e, err := SelectExit(routers)
	if err != nil {
		t.Fatalf("SelectExit: %v", err)
	}
	if !hasFlag(e, "Exit") {
		t.Fatal("selected exit lacks Exit flag")
	}
	// Middle: MockDirectory has mockmiddle, which is neither Guard nor Exit,
	// so SelectMiddle should find it.
	m, err := SelectMiddle(routers)
	if err != nil {
		t.Fatalf("SelectMiddle: %v", err)
	}
	if hasFlag(m, "Guard") || hasFlag(m, "Exit") {
		t.Fatalf("selected middle has Guard/Exit flag: %+v", m.Flags)
	}
}

func TestMockDirectory(t *testing.T) {
	routers := MockDirectory()
	if len(routers) != 3 {
		t.Fatalf("mock dir has %d relays, want 3", len(routers))
	}
	for _, r := range routers {
		if r.OnionKey == ([32]byte{}) {
			t.Fatalf("relay %s has zero onion key", r.Nickname)
		}
		if r.Address == "" {
			t.Fatalf("relay %s has empty address", r.Nickname)
		}
	}
}

func TestParseConsensusMeta(t *testing.T) {
	text := []byte("network-status-version 3 microdesc\n" +
		"vote-status consensus\n" +
		"valid-after 2026-09-24 00:00:00\n" +
		"fresh-until 2026-09-24 01:00:00\n" +
		"valid-until 2026-09-24 03:00:00\n" +
		"directory-footer\n")
	meta, err := ParseConsensusMeta(text)
	if err != nil {
		t.Fatal(err)
	}
	wantVA := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	wantFU := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
	wantVU := time.Date(2026, 9, 24, 3, 0, 0, 0, time.UTC)
	// time.Parse defaults to UTC.
	if !meta.ValidAfter.Equal(wantVA) {
		t.Errorf("ValidAfter = %v, want %v", meta.ValidAfter, wantVA)
	}
	if !meta.FreshUntil.Equal(wantFU) {
		t.Errorf("FreshUntil = %v, want %v", meta.FreshUntil, wantFU)
	}
	if !meta.ValidUntil.Equal(wantVU) {
		t.Errorf("ValidUntil = %v, want %v", meta.ValidUntil, wantVU)
	}
}

func TestParseConsensusMetaMissing(t *testing.T) {
	// No fresh-until line.
	text := []byte("network-status-version 3 microdesc\n" +
		"valid-after 2026-09-24 00:00:00\n" +
		"valid-until 2026-09-24 03:00:00\n")
	if _, err := ParseConsensusMeta(text); err == nil {
		t.Fatal("expected error for missing fresh-until")
	}
}
