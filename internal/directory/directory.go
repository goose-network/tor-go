// Package directory parses Tor directory documents (consensus + microdescriptors)
// into RouterIdentity values that the link and circuit layers can use.
//
// A Tor client fetches these documents from a directory cache (a relay) over
// a one-hop circuit using BEGIN_DIR, or over a direct TLS connection on the
// directory port. This package provides the parser; fetching is handled by
// the torclient package.
//
// This mirrors src/feature/dirparse/microdesc_parse.c and
// src/feature/dirparse/routerparse.c (the consensus "r" / "m" / "a" lines and
// the microdescriptor "onion-key" / "ntor-onion-key" lines).
package directory

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/proxy/tor-go/internal/link"
)

// ConsensusMeta holds the validity timestamps parsed from a consensus
// document's header. A client should re-fetch the consensus before
// FreshUntil (the document is "fresh" until then, "valid" until ValidUntil).
type ConsensusMeta struct {
	ValidAfter  time.Time
	FreshUntil  time.Time
	ValidUntil  time.Time
}

// ParseConsensusMeta extracts the validity timestamps from a consensus
// document. Returns an error if any of the three required header lines are
// missing or malformed.
func ParseConsensusMeta(text []byte) (*ConsensusMeta, error) {
	meta := &ConsensusMeta{}
	sc := bufio.NewScanner(bytes.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	got := 0
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "valid-after "):
			t, err := time.Parse("2006-01-02 15:04:05", strings.TrimPrefix(line, "valid-after "))
			if err != nil {
				return nil, fmt.Errorf("directory: parse valid-after: %w", err)
			}
			meta.ValidAfter = t
			got++
		case strings.HasPrefix(line, "fresh-until "):
			t, err := time.Parse("2006-01-02 15:04:05", strings.TrimPrefix(line, "fresh-until "))
			if err != nil {
				return nil, fmt.Errorf("directory: parse fresh-until: %w", err)
			}
			meta.FreshUntil = t
			got++
		case strings.HasPrefix(line, "valid-until "):
			t, err := time.Parse("2006-01-02 15:04:05", strings.TrimPrefix(line, "valid-until "))
			if err != nil {
				return nil, fmt.Errorf("directory: parse valid-until: %w", err)
			}
			meta.ValidUntil = t
			got++
		}
		if got == 3 {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if got != 3 {
		return nil, fmt.Errorf("directory: consensus missing validity timestamps (found %d/3)", got)
	}
	return meta, nil
}

// Router is a parsed relay entry combining consensus routing info with its
// microdescriptor.
type Router struct {
	link.RouterIdentity
	// Microdescriptor digest (sha256), used to match consensus "m" lines to
	// microdescriptors.
	MicrodescDigest [32]byte
	// Flags from the consensus (Guard, Exit, Fast, Stable, ...).
	Flags []string
	// Bandwidth in bytes/sec from the microdescriptor ("w Bandwidth=" line).
	Bandwidth uint64
	// IPv6Addr is the relay's IPv6 OR address (host:port), from the consensus
	// "a" line. Empty if the relay has no advertised IPv6 address.
	IPv6Addr string
	// ExitPolicy is the parsed short exit policy from the microdescriptor "p"
	// line. Nil means no policy advertised (treat as no exit).
	ExitPolicy *ShortPolicy
	// IPv6ExitPolicy is the parsed IPv6 exit policy from the "p6" line.
	IPv6ExitPolicy *ShortPolicy
	// ORPort / DirPort from the consensus "r" line.
	ORPort  uint16
	DirPort uint16
}

// ShortPolicy is a microdescriptor short exit policy: a list of port ranges
// that are either all accepted (IsAccept) or all rejected.
type ShortPolicy struct {
	// IsAccept is true if the listed ports are accepted (and all others
	// rejected); false if the listed ports are rejected (and all others
	// accepted).
	IsAccept bool
	// Entries is the list of [low,high] inclusive port ranges.
	Entries []ShortPolicyEntry
}

// ShortPolicyEntry is an inclusive port range [Low, High].
type ShortPolicyEntry struct {
	Low, High uint16
}

// AllowsPort reports whether the policy permits connections to port p.
func (sp *ShortPolicy) AllowsPort(p uint16) bool {
	inList := false
	for _, e := range sp.Entries {
		if p >= e.Low && p <= e.High {
			inList = true
			break
		}
	}
	if sp.IsAccept {
		return inList
	}
	return !inList
}

// IsRejectAll reports whether the policy rejects every port.
func (sp *ShortPolicy) IsRejectAll() bool {
	return !sp.IsAccept && len(sp.Entries) == 0
}

// ParseShortPolicy parses a microdescriptor short exit policy string such as
// "accept 80,443" or "reject 1-65535". Returns nil on a malformed input.
func ParseShortPolicy(summary string) *ShortPolicy {
	sp := &ShortPolicy{}
	s := summary
	if len(s) >= 7 && s[:7] == "accept " {
		sp.IsAccept = true
		s = s[7:]
	} else if len(s) >= 7 && s[:7] == "reject " {
		sp.IsAccept = false
		s = s[7:]
	} else {
		return nil
	}
	if s == "" {
		return sp
	}
	for _, tok := range splitCommas(s) {
		if tok == "" {
			continue
		}
		lo, hi := parsePortRange(tok)
		if lo == 0 {
			return nil
		}
		sp.Entries = append(sp.Entries, ShortPolicyEntry{Low: lo, High: hi})
	}
	return sp
}

// splitCommas splits s on commas, dropping empty fields.
func splitCommas(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// parsePortRange parses a port or port range ("80" or "80-443"). Returns
// (low, high); low==0 on error.
func parsePortRange(tok string) (uint16, uint16) {
	dash := -1
	for i := 0; i < len(tok); i++ {
		if tok[i] == '-' {
			dash = i
			break
		}
	}
	if dash < 0 {
		p := parseUint16(tok)
		return p, p
	}
	lo := parseUint16(tok[:dash])
	hi := parseUint16(tok[dash+1:])
	if lo == 0 || hi == 0 || hi < lo {
		return 0, 0
	}
	return lo, hi
}

func parseUint16(s string) uint16 {
	var v uint16
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		v = v*10 + uint16(c-'0')
		if v > 65535 {
			return 0
		}
	}
	return v
}

// ParseProtoVer parses a microdescriptor "pr" line value such as
// "FlowCtrl=2 Cons=2 Relay=1-2" into a map from protocol name to its version
// range string. Returns nil on empty input.
func ParseProtoVer(s string) map[string]string {
	out := make(map[string]string)
	for _, tok := range splitSpaces(s) {
		if tok == "" {
			continue
		}
		eq := -1
		for i := 0; i < len(tok); i++ {
			if tok[i] == '=' {
				eq = i
				break
			}
		}
		if eq < 0 {
			continue
		}
		out[tok[:eq]] = tok[eq+1:]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func splitSpaces(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// ParseConsensus parses a (micro)consensus document and returns a map from
// the base64 identity digest to a partial Router (consensus fields only; the
// onion key is filled in later from the microdescriptor).
//
// Relevant consensus lines:
//
//	r <nickname> <identity(base64)> <digest> <pub> <datetime> <ip> <orport> <dirport>
//	a <ipv6:port>
//	s <flags...>
//	m <microdesc-digest(base64-padded-sha256)>
//	pr ...
func ParseConsensus(text []byte) (map[string]*Router, error) {
	out := make(map[string]*Router)
	sc := bufio.NewScanner(bytes.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var current *Router
	for sc.Scan() {
		line := sc.Text()
		if len(line) == 0 {
			continue
		}
		switch line[0] {
		case 'r':
			current = parseRLine(line)
			if current != nil {
				// Key by hex identity digest.
				out[hex.EncodeToString(current.IDDigest[:])] = current
			}
		case 'a':
			if current != nil {
				parseALine(line, current)
			}
		case 's':
			if current != nil {
				current.Flags = strings.Fields(line[2:])
			}
		case 'm':
			if current != nil {
				parseMLine(line, current)
			}
		case 'w':
			// bandwidth weight; ignore (we use the microdesc w Bandwidth=)
		case 'p':
			// "p" (exit policy) and "pr" (protocol versions) appear in
			// microdescriptors, not the consensus; ignore both here. The
			// microdescriptor "p"/"pr" lines are parsed in ParseMicrodescriptors.
		case 'v':
			// router protocol versions (older form); ignore.
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseRLine parses an "r" line.
func parseRLine(line string) *Router {
	// r <nickname> <identity> <digest> <pub> <YYYY-MM-DD> <HH:MM:SS> <ip> <orport> <dirport>
	fields := strings.Fields(line)
	if len(fields) < 9 || fields[0] != "r" {
		return nil
	}
	r := &Router{}
	r.Nickname = fields[1]
	id, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil || len(id) != 20 {
		return nil
	}
	copy(r.IDDigest[:], id)
	r.Address = fmt.Sprintf("%s:%s", fields[6], fields[7])
	r.ORPort = parseUint16(fields[7])
	if len(fields) >= 9 {
		r.DirPort = parseUint16(fields[8])
	}
	return r
}

// parseALine parses an "a" line (IPv6 OR address, "ipv6:port").
func parseALine(line string, r *Router) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	val := fields[1]
	// The value is an IPv6 address with a port, e.g. "[2001:db8::1]:9001" or
	// "2001:db8::1:9001". Tor uses the bracketed form. We store it verbatim as
	// the IPv6 OR address.
	if strings.HasPrefix(val, "[") {
		// "[addr]:port"
		r.IPv6Addr = val
		return
	}
	// Unbracketed: the last colon separates the port.
	for i := len(val) - 1; i >= 0; i-- {
		if val[i] == ':' {
			r.IPv6Addr = val
			return
		}
	}
}

// parseMLine parses an "m" line (microdescriptor digest).
func parseMLine(line string, r *Router) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	// The digest is base64 of the sha256, without padding in the consensus;
	// add padding.
	d := fields[1]
	for len(d)%4 != 0 {
		d += "="
	}
	dec, err := base64.StdEncoding.DecodeString(d)
	if err != nil || len(dec) != 32 {
		return
	}
	copy(r.MicrodescDigest[:], dec)
}

// ParseMicrodescriptors parses a batch of microdescriptors and merges them
// into the routers map (keyed by hex identity digest). Each microdescriptor
// is separated by a blank line and starts with "onion-key".
//
// Relevant microdescriptor lines:
//
//	onion-key <RSA base64 block>      (legacy; ignored)
//	ntor-onion-key <base64>           (Curve25519 public key)
//	p <exit-policy>                   (ignored)
//	w Bandwidth=<bytes/sec>
//	id ed25519 <base64-no-pad>
func ParseMicrodescriptors(text []byte, routers map[string]*Router) error {
	// A microdescriptor is a contiguous block of non-blank lines beginning
	// with "onion-key". Its digest (as referenced by the consensus "m" line)
	// is the SHA-256 of the microdescriptor body, including a trailing
	// newline. We split the input on blank lines and hash each block.
	sc := bufio.NewScanner(bytes.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 4<<20)

	var (
		blockLines []string
		ntorKey    [32]byte
		haveNtor   bool
		edKey      [32]byte
		haveEd     bool
		bw         uint64
		exitPol    *ShortPolicy
		ipv6Pol    *ShortPolicy
		protoVer   map[string]string
	)
	flush := func() {
		if len(blockLines) == 0 {
			return
		}
		// Reconstruct the body and compute its sha256. The body is the lines
		// joined by newlines with a trailing newline.
		var body bytes.Buffer
		for _, l := range blockLines {
			body.WriteString(l)
			body.WriteByte('\n')
		}
		digest := sha256.Sum256(body.Bytes())
		// Find the router whose microdesc digest matches.
		for _, r := range routers {
			if r.MicrodescDigest == digest {
				if haveNtor {
					r.OnionKey = ntorKey
				}
				if haveEd {
					r.Ed25519ID = edKey
				}
				r.Bandwidth = bw
				if exitPol != nil {
					r.ExitPolicy = exitPol
				}
				if ipv6Pol != nil {
					r.IPv6ExitPolicy = ipv6Pol
				}
				if protoVer != nil {
					r.ProtoVer = protoVer
				}
			}
		}
		blockLines = nil
		haveNtor, haveEd = false, false
		bw = 0
		exitPol, ipv6Pol = nil, nil
		protoVer = nil
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			// Blank line: end of current microdescriptor.
			flush()
			continue
		}
		if strings.HasPrefix(line, "onion-key") && len(blockLines) > 0 {
			// A new microdescriptor starts without a blank separator.
			flush()
		}
		blockLines = append(blockLines, line)
		switch {
		case strings.HasPrefix(line, "ntor-onion-key "):
			key := strings.TrimSpace(line[len("ntor-onion-key "):])
			dec, err := base64.StdEncoding.DecodeString(padB64(key))
			if err == nil && len(dec) == 32 {
				copy(ntorKey[:], dec)
				haveNtor = true
			}
		case strings.HasPrefix(line, "id ed25519 "):
			key := strings.TrimSpace(line[len("id ed25519 "):])
			dec, err := base64.StdEncoding.DecodeString(padB64(key))
			if err == nil && len(dec) == 32 {
				copy(edKey[:], dec)
				haveEd = true
			}
		case strings.HasPrefix(line, "w Bandwidth="):
			val := strings.TrimSpace(line[len("w Bandwidth="):])
			var v uint64
			fmt.Sscanf(val, "%d", &v)
			bw = v
		case strings.HasPrefix(line, "p "):
			// Short exit policy: "p accept 80,443" or "p reject 1-65535".
			exitPol = ParseShortPolicy(strings.TrimSpace(line[2:]))
		case strings.HasPrefix(line, "p6 "):
			ipv6Pol = ParseShortPolicy(strings.TrimSpace(line[3:]))
		case strings.HasPrefix(line, "pr "):
			protoVer = ParseProtoVer(strings.TrimSpace(line[3:]))
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

// padB64 adds standard base64 padding.
func padB64(s string) string {
	for len(s)%4 != 0 {
		s += "="
	}
	return s
}

// SelectGuard picks a relay with the Guard flag from the routers map, weighted
// by advertised bandwidth (mirrors node_sl_choose_by_bandwidth with
// WEIGHT_FOR_GUARD). Falls back to any relay with an ntor key if no Guard-flagged
// relay is available. Used by the client at startup.
func SelectGuard(routers map[string]*Router) (*Router, error) {
	var eligible []*Router
	for _, r := range routers {
		if hasFlag(r, "Guard") && r.OnionKey != ([32]byte{}) {
			eligible = append(eligible, r)
		}
	}
	if len(eligible) == 0 {
		// Fall back to any relay with an ntor key.
		for _, r := range routers {
			if r.OnionKey != ([32]byte{}) {
				eligible = append(eligible, r)
			}
		}
	}
	if len(eligible) == 0 {
		return nil, fmt.Errorf("directory: no suitable guard found among %d relays", len(routers))
	}
	return weightedChoose(eligible), nil
}

// SelectExit picks a relay with the Exit flag for the circuit's exit hop,
// weighted by advertised bandwidth (WEIGHT_FOR_EXIT).
func SelectExit(routers map[string]*Router) (*Router, error) {
	var eligible []*Router
	for _, r := range routers {
		if hasFlag(r, "Exit") && r.OnionKey != ([32]byte{}) {
			eligible = append(eligible, r)
		}
	}
	if len(eligible) == 0 {
		return nil, fmt.Errorf("directory: no suitable exit found")
	}
	return weightedChoose(eligible), nil
}

// SelectMiddle picks any non-Guard, non-Exit relay (with an ntor key) for a
// middle hop, weighted by advertised bandwidth (WEIGHT_FOR_MID).
func SelectMiddle(routers map[string]*Router) (*Router, error) {
	var eligible []*Router
	for _, r := range routers {
		if r.OnionKey != ([32]byte{}) && !hasFlag(r, "Guard") && !hasFlag(r, "Exit") {
			eligible = append(eligible, r)
		}
	}
	if len(eligible) == 0 {
		return nil, fmt.Errorf("directory: no suitable middle found")
	}
	return weightedChoose(eligible), nil
}

// weightedChoose picks one router from eligible, with probability proportional
// to its advertised Bandwidth. This mirrors choose_array_element_by_weight +
// scale_array_elements_to_u64 in node_select.c: each node's bandwidth is its
// weight, we draw a uniform random value in [0, total) and walk the cumulative
// sum. If all weights are zero, the choice is uniform at random.
func weightedChoose(eligible []*Router) *Router {
	// Compute total weight. Use uint64 to avoid overflow on large consensuses.
	var total uint64
	for _, r := range eligible {
		total += r.Bandwidth
	}
	if total == 0 {
		// Uniform random selection.
		idx := cryptoRandInt(len(eligible))
		return eligible[idx]
	}
	randVal := cryptoRandUint64(total)
	var cum uint64
	for _, r := range eligible {
		cum += r.Bandwidth
		if randVal < cum {
			return r
		}
	}
	// Floating-point-free fallback: rounding could leave randVal == total-1
	// past the last entry only if total underflowed, which can't happen here.
	return eligible[len(eligible)-1]
}

func hasFlag(r *Router, f string) bool {
	for _, x := range r.Flags {
		if x == f {
			return true
		}
	}
	return false
}

// cryptoRandInt returns a uniform random int in [0, n). It mirrors Tor's
// crypto_rand_int. n must be > 0.
func cryptoRandInt(n int) int {
	if n <= 0 {
		return 0
	}
	// Rejection sampling to avoid modulo bias, matching crypto_rand_int's
	// approach of drawing from a range that is a multiple of n.
	// For simplicity and correctness we use a uint64 draw with rejection.
	// Find the largest multiple of n <= MaxUint64+1.
	limit := ^uint64(0)
	// Number of full buckets of size n that fit in [0, limit].
	// We want a value in [0, n*buckets) and take mod n.
	// buckets = floor((limit+1)/n), but limit+1 overflows; use limit/n.
	buckets := limit / uint64(n)
	if buckets == 0 {
		buckets = 1
	}
	threshold := buckets * uint64(n)
	for {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			// crypto/rand should not fail; fall back to a deterministic-ish
			// choice rather than panicking.
			return int(b[0]) % n
		}
		v := binary.BigEndian.Uint64(b[:])
		if v < threshold {
			return int(v % uint64(n))
		}
	}
}

// cryptoRandUint64 returns a uniform random uint64 in [0, max). It mirrors
// Tor's crypto_rand_uint64. max must be > 0.
func cryptoRandUint64(max uint64) uint64 {
	if max == 0 {
		return 0
	}
	buckets := ^uint64(0) / max
	if buckets == 0 {
		buckets = 1
	}
	threshold := buckets * max
	for {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return binary.BigEndian.Uint64(b[:]) % max
		}
		v := binary.BigEndian.Uint64(b[:])
		if v < threshold {
			return v % max
		}
	}
}
