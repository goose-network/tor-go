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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/proxy/tor-go/internal/link"
)

// Router is a parsed relay entry combining consensus routing info with its
// microdescriptor.
type Router struct {
	link.RouterIdentity
	// Microdescriptor digest (sha256), used to match consensus "m" lines to
	// microdescriptors.
	MicrodescDigest [32]byte
	// Flags from the consensus (Guard, Exit, Fast, Stable, ...).
	Flags []string
	// Bandwidth in bytes/sec from the microdescriptor.
	Bandwidth uint64
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
			// bandwidth weight; ignore
		case 'p':
			// exit policy; ignore for now
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
	return r
}

// parseALine parses an "a" line (IPv6 OR address).
func parseALine(line string, r *Router) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	// fields[1] is "ipv6:port"; we keep the IPv4 address from the r line as
	// primary and could store IPv6 here. For simplicity we ignore IPv6 for
	// now.
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
			}
		}
		blockLines = nil
		haveNtor, haveEd = false, false
		bw = 0
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

// SelectGuard picks a relay with the Guard flag from the routers map. It
// returns the first suitable guard (a real implementation would weigh by
// bandwidth and persist a guard). Used by the client at startup.
func SelectGuard(routers map[string]*Router) (*Router, error) {
	for _, r := range routers {
		if hasFlag(r, "Guard") && r.OnionKey != ([32]byte{}) {
			return r, nil
		}
	}
	// Fall back to any relay with an ntor key.
	for _, r := range routers {
		if r.OnionKey != ([32]byte{}) {
			return r, nil
		}
	}
	return nil, fmt.Errorf("directory: no suitable guard found among %d relays", len(routers))
}

// SelectExit picks a relay with the Exit flag for the circuit's exit hop.
func SelectExit(routers map[string]*Router) (*Router, error) {
	for _, r := range routers {
		if hasFlag(r, "Exit") && r.OnionKey != ([32]byte{}) {
			return r, nil
		}
	}
	return nil, fmt.Errorf("directory: no suitable exit found")
}

// SelectMiddle picks any relay (with an ntor key) for a middle hop.
func SelectMiddle(routers map[string]*Router) (*Router, error) {
	for _, r := range routers {
		if r.OnionKey != ([32]byte{}) && !hasFlag(r, "Guard") && !hasFlag(r, "Exit") {
			return r, nil
		}
	}
	return nil, fmt.Errorf("directory: no suitable middle found")
}

func hasFlag(r *Router, f string) bool {
	for _, x := range r.Flags {
		if x == f {
			return true
		}
	}
	return false
}
