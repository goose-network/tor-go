package directory

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/goose-network/tor-go/internal/link"
)

// MockDirectory returns a small synthetic directory of relays for testing.
// Each relay has a freshly-generated Curve25519 onion key and a deterministic
// identity digest. The relays are not real and cannot be connected to over
// the public Tor network; they are used by the in-process e2e test harness,
// which runs a mock relay server implementing the link + circuit protocol.
func MockDirectory() map[string]*Router {
	routers := make(map[string]*Router)
	names := []string{"mockguard", "mockmiddle", "mockexit"}
	flags := [][]string{{"Guard", "Fast", "Stable", "Valid"}, {"Fast", "Stable", "Valid"}, {"Exit", "Fast", "Stable", "Valid"}}
	for i, name := range names {
		r := &Router{}
		r.Nickname = name
		// Deterministic identity digest from the name.
		h := sha256.Sum256([]byte(name))
		copy(r.IDDigest[:], h[:20])
		// Deterministic onion key from the name (32 bytes).
		ok := sha256.Sum256([]byte(name + "-onionkey"))
		copy(r.OnionKey[:], ok[:])
		// Ed25519 id (deterministic).
		ed := sha256.Sum256([]byte(name + "-ed25519"))
		copy(r.Ed25519ID[:], ed[:])
		// Microdesc digest (deterministic).
		md := sha256.Sum256([]byte(name + "-microdesc"))
		copy(r.MicrodescDigest[:], md[:])
		r.Flags = flags[i]
		r.Bandwidth = 100000
		// Address is filled in by the test harness when it starts the mock
		// relay; default to a placeholder.
		r.Address = fmt.Sprintf("127.0.0.1:%d", 9000+i)
		routers[encodeID(r.IDDigest)] = r
	}
	return routers
}

// encodeID returns the hex encoding of a 20-byte identity digest, matching
// the key format used by ParseConsensus.
func encodeID(id [20]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 40)
	for i, b := range id {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&0x0f]
	}
	return string(out)
}

// SetMockAddress updates the address of a mock relay by nickname. Used by the
// test harness to point a relay at the actual listening port of a mock relay
// server.
func SetMockAddress(routers map[string]*Router, nickname, addr string) {
	for _, r := range routers {
		if r.Nickname == nickname {
			r.Address = addr
			return
		}
	}
}

// FindByNickname returns the router with the given nickname, or nil.
func FindByNickname(routers map[string]*Router, nickname string) *Router {
	for _, r := range routers {
		if r.Nickname == nickname {
			return r
		}
	}
	return nil
}

// EncodeOnionKeyBase64 returns the base64 encoding of a relay's onion key
// (for diagnostics).
func EncodeOnionKeyBase64(r *link.RouterIdentity) string {
	return base64.StdEncoding.EncodeToString(r.OnionKey[:])
}
