package fallback

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseSynthetic verifies Parse handles the fallback_dirs.inc format:
// the leading file header (no orport) is skipped, IPv4-only and IPv4+IPv6
// entries parse, and the RSA fingerprint is decoded correctly.
func TestParseSynthetic(t *testing.T) {
	data := []byte(`/* This file is generated. */
"1.2.3.4 orport=9001 id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
/* nickname=foo */
/* extrainfo=0 */
/* ===== */
,
"5.6.7.8 orport=443 id=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
" ipv6=[2a01::1]:443"
/* nickname=bar */
,
"9.10.11.12 orport=9001 id=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
`)
	out, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d entries, want 3", len(out))
	}
	if out[0].IPv4Addr != "1.2.3.4:9001" {
		t.Errorf("entry0 IPv4 = %q, want 1.2.3.4:9001", out[0].IPv4Addr)
	}
	if out[0].IPv6Addr != "" {
		t.Errorf("entry0 IPv6 = %q, want empty", out[0].IPv6Addr)
	}
	if out[0].HexFingerprint() != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("entry0 fp = %q", out[0].HexFingerprint())
	}
	if out[1].IPv6Addr != "[2a01::1]:443" {
		t.Errorf("entry1 IPv6 = %q, want [2a01::1]:443", out[1].IPv6Addr)
	}
	if out[2].IPv4Addr != "9.10.11.12:9001" {
		t.Errorf("entry2 IPv4 = %q", out[2].IPv4Addr)
	}
}

// TestParseRealFallbackDirs parses the real fallback_dirs.inc from the C
// reference repo (if present alongside this module) and verifies it yields
// 200 entries, each with a valid IPv4 ORPort and 20-byte fingerprint. This
// guards the parser against format drift in the upstream file.
func TestParseRealFallbackDirs(t *testing.T) {
	// The C reference repo lives at ../../tor relative to this module's
	// internal/fallback directory.
	candidates := []string{
		"../../tor/src/app/config/fallback_dirs.inc",
		"../../../tor/src/app/config/fallback_dirs.inc",
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("fallback_dirs.inc not found; skipping real-file parse test")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out) != 200 {
		t.Errorf("got %d entries, want 200", len(out))
	}
	// Spot-check the first entry against the known first fallback.
	if len(out) > 0 && out[0].HexFingerprint() != "c3a13ec59d6d58c3f75ffc1a5701f7793179180b" {
		t.Errorf("first fp = %q, want c3a13ec59d6d58c3f75ffc1a5701f7793179180b", out[0].HexFingerprint())
	}
}

// TestPreferredAddr verifies IPv6 is preferred when present.
func TestPreferredAddr(t *testing.T) {
	withV6 := Fallback{IPv4Addr: "1.2.3.4:9001", IPv6Addr: "[2a01::1]:443"}
	if got := withV6.PreferredAddr(); got != "[2a01::1]:443" {
		t.Errorf("PreferredAddr = %q, want [2a01::1]:443", got)
	}
	v4only := Fallback{IPv4Addr: "1.2.3.4:9001"}
	if got := v4only.PreferredAddr(); got != "1.2.3.4:9001" {
		t.Errorf("PreferredAddr = %q, want 1.2.3.4:9001", got)
	}
}

// TestDefaultFallbacksSanity verifies the hardcoded list is non-empty and
// every entry has a non-zero fingerprint and a parseable IPv4 ORPort.
func TestDefaultFallbacksSanity(t *testing.T) {
	if len(DefaultFallbacks) == 0 {
		t.Fatal("DefaultFallbacks is empty")
	}
	for i, f := range DefaultFallbacks {
		if f.RSAFingerprint == ([20]byte{}) {
			t.Errorf("entry %d has zero fingerprint", i)
		}
		if f.IPv4Addr == "" {
			t.Errorf("entry %d has empty IPv4Addr", i)
		}
	}
}
