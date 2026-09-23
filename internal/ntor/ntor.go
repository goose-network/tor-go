// Package ntor implements the ntor circuit-extension handshake
// (ntor-curve25519-sha256-1) used by Tor to establish per-hop keys on a
// circuit. This mirrors src/core/crypto/onion_ntor.c in the C reference
// implementation.
//
// The handshake is a one-way authenticated key exchange based on
// Curve25519 (X25519) Diffie-Hellman, HMAC-SHA256 and HKDF-SHA256.
package ntor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// randRead fills b with cryptographically secure random bytes.
func randRead(b []byte) (int, error) { return rand.Read(b) }

// PROTOID is the ntor protocol identifier string.
const PROTOID = "ntor-curve25519-sha256-1"

// Tweak strings used as HMAC keys / HKDF info during the handshake.
const (
	tMac     = PROTOID + ":mac"
	tKey     = PROTOID + ":key_extract"
	tVerify  = PROTOID + ":verify"
	tExpand  = PROTOID + ":key_expand"
	serverStr = "Server"
)

// OnionskinLen is the length of the client->server onionskin (84 bytes:
// 20-byte router identity digest + 32-byte router onion key + 32-byte
// client ephemeral public key).
const OnionskinLen = 84

// ReplyLen is the length of the server->client reply (64 bytes: 32-byte
// server ephemeral public key + 32-byte MAC).
const ReplyLen = 64

// digestLen is the SHA-1 identity digest length used as the router ID.
const digestLen = 20

// pubKeyLen is the Curve25519 public key length.
const pubKeyLen = 32

// outputLen is the raw X25519 shared-secret length.
const outputLen = 32

// ClientState holds the client-side state between sending an onionskin and
// receiving the server reply.
type ClientState struct {
	routerID [digestLen]byte // identity digest of the target router
	pubkeyB  [pubKeyLen]byte // onion (Curve25519) public key of the target
	seckeyX  [pubKeyLen]byte // client ephemeral secret key
	pubkeyX  [pubKeyLen]byte // client ephemeral public key
}

// hTweak computes HMAC-SHA256(key=tweak, msg=inp) into out (32 bytes).
func hTweak(out *[32]byte, inp []byte, tweak string) {
	mac := hmac.New(sha256.New, []byte(tweak))
	mac.Write(inp)
	copy(out[:], mac.Sum(nil))
}

// Create performs the first client-side step of the ntor handshake for a
// server whose 20-byte identity digest is routerID and whose Curve25519
// onion key is routerKey. It returns the 84-byte onionskin and the opaque
// client state needed to complete the handshake.
func Create(routerID, routerKey []byte) (onionskin []byte, state *ClientState, err error) {
	if len(routerID) != digestLen {
		return nil, nil, errors.New("ntor: routerID must be 20 bytes")
	}
	if len(routerKey) != pubKeyLen {
		return nil, nil, errors.New("ntor: routerKey must be 32 bytes")
	}

	state = &ClientState{}
	copy(state.routerID[:], routerID)
	copy(state.pubkeyB[:], routerKey)

	// Generate an ephemeral Curve25519 keypair.
	if _, err := randRead(state.seckeyX[:]); err != nil {
		return nil, nil, err
	}
	// Clamp the private scalar per RFC 7748.
	state.seckeyX[0] &= 248
	state.seckeyX[31] &= 127
	state.seckeyX[31] |= 64

	pubX, err := curve25519.X25519(state.seckeyX[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	copy(state.pubkeyX[:], pubX)

	onionskin = make([]byte, OnionskinLen)
	copy(onionskin[0:digestLen], state.routerID[:])
	copy(onionskin[digestLen:digestLen+pubKeyLen], state.pubkeyB[:])
	copy(onionskin[digestLen+pubKeyLen:], state.pubkeyX[:])
	return onionskin, state, nil
}

// ClientHandshake performs the final client-side step. Given the state from
// Create and the server's 64-byte reply, it verifies the server's MAC and
// derives keyLen bytes of key material. It returns an error if
// authentication fails.
func (s *ClientState) ClientHandshake(reply []byte, keyLen int) (keys []byte, err error) {
	if len(reply) != ReplyLen {
		return nil, errors.New("ntor: reply must be 64 bytes")
	}
	var pubkeyY [pubKeyLen]byte
	copy(pubkeyY[:], reply[0:pubKeyLen])
	authCandidate := reply[pubKeyLen:]

	// Compute the two DH shared secrets: exp(X, Y) and exp(X, B).
	xy, err := curve25519.X25519(s.seckeyX[:], pubkeyY[:])
	if err != nil {
		return nil, err
	}
	xb, err := curve25519.X25519(s.seckeyX[:], s.pubkeyB[:])
	if err != nil {
		return nil, err
	}
	if isZero(xy) || isZero(xb) {
		return nil, errors.New("ntor: zero output from curve25519 handshake")
	}

	// Build secret_input:
	//   EXP(X,y) || EXP(X,B) || B || X || Y || PROTOID
	secretInput := make([]byte, 0, outputLen*2+digestLen+pubKeyLen*3+len(PROTOID))
	secretInput = append(secretInput, xy...)
	secretInput = append(secretInput, xb...)
	secretInput = append(secretInput, s.routerID[:]...)
	secretInput = append(secretInput, s.pubkeyB[:]...)
	secretInput = append(secretInput, s.pubkeyX[:]...)
	secretInput = append(secretInput, pubkeyY[:]...)
	secretInput = append(secretInput, []byte(PROTOID)...)

	// verify = H_tweak(secret_input, t_verify)
	var verify [32]byte
	hTweak(&verify, secretInput, tVerify)

	// auth_input = verify || B || Y || X || PROTOID || "Server"
	authInput := make([]byte, 0, 32+digestLen+pubKeyLen*3+len(PROTOID)+len(serverStr))
	authInput = append(authInput, verify[:]...)
	authInput = append(authInput, s.routerID[:]...)
	authInput = append(authInput, s.pubkeyB[:]...)
	authInput = append(authInput, pubkeyY[:]...)
	authInput = append(authInput, s.pubkeyX[:]...)
	authInput = append(authInput, []byte(PROTOID)...)
	authInput = append(authInput, []byte(serverStr)...)

	// auth = H_tweak(auth_input, t_mac)
	var auth [32]byte
	hTweak(&auth, authInput, tMac)

	// Compare against the server's MAC.
	if !hmac.Equal(auth[:], authCandidate) {
		return nil, errors.New("ntor: bad server MAC (wrong onion key?)")
	}

	// Derive key material via HKDF-SHA256 (RFC 5869), matching Tor's
	// crypto_expand_key_material_rfc5869_sha256(secret_input, t_key,
	// t_expand, ...):
	//   PRK = HMAC-SHA256(salt=t_key, IKM=secret_input)
	//   OKM = HKDF-Expand(PRK, info=t_expand, L=keyLen)
	keys = make([]byte, keyLen)
	h := hkdf.New(sha256.New, secretInput, []byte(tKey), []byte(tExpand))
	if _, err := h.Read(keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// isZero reports whether b is all zero bytes.
func isZero(b []byte) bool {
	var z byte
	for _, x := range b {
		z |= x
	}
	return z == 0
}
