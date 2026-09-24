// Package fallback provides the hardcoded list of fallback directory
// caches (src/app/config/fallback_dirs.inc in the C reference) and a parser
// for its line format.
//
// A fallback directory is a relay that volunteers to serve directory
// documents (consensus, microdescriptors, authority certs) to clients that
// have not yet obtained a consensus. The client bootstraps by contacting a
// fallback over a one-hop CREATE_FAST circuit (the fallback's onion key is
// not in the hardcoded list, so ntor is not possible) with BEGIN_DIR, falling
// back from one to the next on failure. This avoids a hard dependency on the
// directory authorities, which are a small, well-known set and therefore an
// easier target for censors.
//
// The fallback list carries only each relay's IPv4 (and optional IPv6)
// ORPort and RSA identity fingerprint (a 20-byte SHA-1 digest, hex-encoded).
// The identity is verified against the relay's TLS certificate during the
// link handshake (link.DialWithUpstream), so the lack of an onion key in the
// list is not a security problem: the TLS link authenticates the relay, and
// CREATE_FAST's lack of forward secrecy is acceptable for a one-hop circuit
// to a directory cache.
//
// The list is curated at build time and will go stale as relays churn; the
// parser (Parse) allows regenerating it from a current fallback_dirs.inc.
package fallback

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Fallback is a single fallback directory cache: its ORPort address(es) and
// RSA identity fingerprint.
type Fallback struct {
	// IPv4Addr is the IPv4 ORPort address, "IP:port".
	IPv4Addr string
	// IPv6Addr is the IPv6 ORPort address, "[addr]:port", or empty if the
	// fallback has no IPv6 ORPort.
	IPv6Addr string
	// RSAFingerprint is the 20-byte RSA identity fingerprint (SHA-1 of the
	// relay's long-term RSA identity key).
	RSAFingerprint [20]byte
}

// HexFingerprint returns RSAFingerprint as a lowercase hex string.
func (f Fallback) HexFingerprint() string { return hex.EncodeToString(f.RSAFingerprint[:]) }

// PreferredAddr returns the address to dial first: IPv6 if present, else
// IPv4. (The C client prefers IPv6 when available; see
// fascist_firewall_choose_address_ls.)
func (f Fallback) PreferredAddr() string {
	if f.IPv6Addr != "" {
		return f.IPv6Addr
	}
	return f.IPv4Addr
}

// DefaultFallbacks is a curated list of fallback directory caches, drawn from
// Tor's fallback_dirs.inc. It is intentionally a subset (the full list is
// ~200 relays and churns over time); the parser (Parse) can regenerate a
// current list from a fresh fallback_dirs.inc. Even a dozen fallbacks give
// meaningful censorship resistance for bootstrap, since the client tries them
// in randomized order and falls over on failure.
var DefaultFallbacks = []Fallback{
	{IPv4Addr: "37.221.209.76:9200", IPv6Addr: "[2a01:270:994c::1]:9200", RSAFingerprint: hexFP("C3A13EC59D6D58C3F75FFC1A5701F7793179180B")},
	{IPv4Addr: "185.220.101.102:443", IPv6Addr: "[2a0b:f4c2:4::102]:443", RSAFingerprint: hexFP("9A783CAA9DABA178D9864471E9287045CBFDC726")},
	{IPv4Addr: "89.58.17.212:7444", IPv6Addr: "[2a0a:4cc0:0:e35:c4dd:60ff:fe34:7d02]:7444", RSAFingerprint: hexFP("8B0C858DD20236104D6981F3F95201EF732BF0BF")},
	{IPv4Addr: "204.8.96.161:444", IPv6Addr: "[2620:7:6003::161]:81", RSAFingerprint: hexFP("C218BEFAA0EFFE5565A6FC1EBA46EE4579F4CE87")},
	{IPv4Addr: "64.65.63.4:443", RSAFingerprint: hexFP("FD2BA20C57787DDB69AA6E9AFA8983E683867DD2")},
	{IPv4Addr: "217.160.252.208:9001", IPv6Addr: "[2a01:239:28e:6100::1]:9001", RSAFingerprint: hexFP("2E0973F2D6D62064A481F8031265F143210F3883")},
	{IPv4Addr: "185.4.134.104:9001", IPv6Addr: "[2a02:c500:2:110::8709:9001]:9001", RSAFingerprint: hexFP("C6E3910CBADCA6D2D7E932AB31A038EDD6A6FB79")},
	{IPv4Addr: "37.221.193.44:9001", IPv6Addr: "[2a03:4000:8:3c1::9001]:9001", RSAFingerprint: hexFP("7DA31D79E52D12685BBE8544E3C557F176B0FC84")},
	{IPv4Addr: "151.245.195.201:9001", RSAFingerprint: hexFP("D7E2C53C112C82D14E92FB9C6CBB06E8D0FB88DF")},
	{IPv4Addr: "57.131.29.153:10101", IPv6Addr: "[2001:41d0:2005:100::90a]:10101", RSAFingerprint: hexFP("7374E21203844C2A59EB54FB3FA055CA34D3EA56")},
	{IPv4Addr: "68.209.194.158:9031", RSAFingerprint: hexFP("43C9E44B47BC0A6BC1D8FE80B1AAFCE67AE399CC")},
	{IPv4Addr: "45.80.171.211:587", IPv6Addr: "[2a10:3781:16ea:90:45:80:171:211]:587", RSAFingerprint: hexFP("A69CC8EC35B5C90096AFFC3C10955646B5206347")},
}

// hexFP decodes a 40-char hex RSA fingerprint into 20 bytes. It panics on a
// bad constant (a programming error in DefaultFallbacks), so it is only used
// to initialize the package-level list.
func hexFP(s string) [20]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 20 {
		panic("fallback: bad hardcoded fingerprint: " + s)
	}
	var out [20]byte
	copy(out[:], b)
	return out
}

// Parse parses the fallback_dirs.inc line format into a list of Fallbacks.
// The input is the raw contents of fallback_dirs.inc: a comma-separated list
// of entries, each a sequence of quoted string fragments (the first carries
// "IP orport=PORT id=HEX_FP", an optional second carries
// " ipv6=[addr]:port"), interspersed with /* ... */ comments. Parse extracts
// the IPv4 ORPort, optional IPv6 ORPort, and RSA fingerprint from each entry.
// Entries that fail to parse are skipped with their error accumulated in the
// returned error (non-fatal, mirroring the C client's tolerance of a stale
// list).
func Parse(data []byte) ([]Fallback, error) {
	// Split into entries on commas. Each entry is one fallback.
	entries := strings.Split(string(data), ",")
	var out []Fallback
	var errs []string
	for _, entry := range entries {
		fb, err := parseEntry(entry)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if fb != nil {
			out = append(out, *fb)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("fallback: no valid entries parsed (%d errors: %s)", len(errs), strings.Join(errs, "; "))
	}
	return out, nil
}

// parseEntry parses a single comma-separated entry (which may be empty or a
// header chunk before the first real entry). It returns nil, nil for an entry
// with no "orport=" fragment (e.g. the leading file header).
func parseEntry(entry string) (*Fallback, error) {
	// Collect the quoted string fragments, ignoring /* ... */ comments and
	// whitespace.
	var fragments []string
	for _, line := range strings.Split(entry, "\n") {
		line = strings.TrimSpace(line)
		// Strip a trailing /* ... */ comment on the same line.
		if i := strings.Index(line, "/*"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// A fragment is a quoted string; unquote it.
		if strings.HasPrefix(line, `"`) {
			s, err := strconv.Unquote(line)
			if err != nil {
				return nil, fmt.Errorf("unquote %q: %w", line, err)
			}
			fragments = append(fragments, s)
		}
	}
	if len(fragments) == 0 {
		return nil, nil
	}
	// Join the fragments: the first is "IP orport=PORT id=HEX", subsequent
	// ones are " ipv6=[addr]:port" (with a leading space). Joining preserves
	// the space-separated form.
	joined := strings.Join(fragments, "")
	fields := strings.Fields(joined)
	if len(fields) < 3 {
		return nil, fmt.Errorf("entry has %d fields, need >=3: %q", len(fields), joined)
	}
	fb := &Fallback{}
	// fields[0] is the IPv4 address (no port yet).
	ipv4 := fields[0]
	// fields[1..] are key=value tokens.
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "orport":
			fb.IPv4Addr = net.JoinHostPort(ipv4, v)
		case "id":
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != 20 {
				return nil, fmt.Errorf("bad id %q: %w", v, err)
			}
			copy(fb.RSAFingerprint[:], b)
		case "ipv6":
			// v is "[addr]:port"; strip any surrounding whitespace.
			fb.IPv6Addr = strings.TrimSpace(v)
		}
	}
	if fb.IPv4Addr == "" {
		return nil, errors.New("entry missing orport")
	}
	if fb.RSAFingerprint == ([20]byte{}) {
		return nil, errors.New("entry missing id")
	}
	return fb, nil
}
