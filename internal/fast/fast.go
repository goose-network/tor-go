// Package fast implements the CREATE_FAST circuit handshake
// (tor-spec.txt, "Circuit extension handshakes"; src/core/crypto/onion_fast.c
// in the C reference).
//
// CREATE_FAST is an unauthenticated, non-forward-secure key derivation based
// on SHA-1. It is used only for the first hop of a one-hop circuit to a
// trusted directory cache (a directory authority or a fallback directory)
// whose identity is already known from a hardcoded list, so the lack of
// forward secrecy is acceptable: the TLS link to the relay already
// authenticates it and protects the handshake from eavesdroppers. It must
// never be used for a hop beyond the first or to a relay whose identity is
// not independently verified.
//
// The handshake is:
//
//   - Client sends x (NonceLen random bytes) in a CREATE_FAST cell.
//   - Server replies y || H(x||y) (ReplyLen bytes): y is NonceLen random
//     bytes and H is the TAP key-expansion (crypto_expand_key_material_TAP)
//     over x||y, producing key_out_len + NonceLen bytes; the first NonceLen
//     bytes are the integrity check and the rest are the key material.
//   - Client recomputes H(x||y) and checks it matches the reply's trailing
//     NonceLen bytes, then takes the key material.
//
// The TAP key expansion (crypto_hkdf.c:crypto_expand_key_material_TAP) is:
//
//	for i = 0, 1, 2, ...: digest_i = SHA1(key_in || byte(i))
//	output = digest_0 || digest_1 || ...  (truncated to key_out_len)
//
// where key_in = x || y.
package fast

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
)

// NonceLen is the length of the client and server nonces (DIGEST_LEN = 20
// bytes, SHA-1 output size). CREATE_FAST_LEN in the C reference.
const NonceLen = 20

// ReplyLen is the length of the server's CREATED_FAST reply: y || H(x||y)
// (CREATED_FAST_LEN = DIGEST_LEN*2 in the C reference).
const ReplyLen = NonceLen * 2

// State holds the client's in-progress CREATE_FAST handshake state (the
// nonce x it sent).
type State struct {
	x [NonceLen]byte
}

// Create generates the client's CREATE_FAST onionskin (the random nonce x)
// and returns it together with the state needed to complete the handshake.
// This mirrors fast_onionskin_create (onion_fast.c).
func Create() ([]byte, *State, error) {
	var s State
	if _, err := rand.Read(s.x[:]); err != nil {
		return nil, nil, err
	}
	onionskin := make([]byte, NonceLen)
	copy(onionskin, s.x[:])
	return onionskin, &s, nil
}

// ServerHandshake performs the server side of CREATE_FAST: given the client's
// onionskin (nonce x) and the total key length to derive (keyLen, e.g.
// relaycrypto.TotalKeyLen), it generates a random nonce y and returns the
// CREATED_FAST reply (y || H(x||y), ReplyLen bytes) and the derived key
// material (keyLen bytes). The key material is the bytes immediately after
// the integrity check in TAP-Expand(x||y, keyLen+NonceLen). This mirrors
// fast_server_handshake (onion_fast.c). It is exported so an in-process test
// relay (and any server implementation) can share the canonical TAP
// expansion with the client.
func ServerHandshake(onionskin []byte, keyLen int) (reply, keys []byte, err error) {
	if len(onionskin) != NonceLen {
		return nil, nil, errors.New("fast: bad CREATE_FAST onionskin length")
	}
	var y [NonceLen]byte
	if _, err := rand.Read(y[:]); err != nil {
		return nil, nil, err
	}
	keyIn := make([]byte, 0, NonceLen*2)
	keyIn = append(keyIn, onionskin...)
	keyIn = append(keyIn, y[:]...)
	out := expandTAP(keyIn, keyLen+NonceLen)
	reply = make([]byte, ReplyLen)
	copy(reply[:NonceLen], y[:])
	copy(reply[NonceLen:], out[:NonceLen])
	keys = make([]byte, keyLen)
	copy(keys, out[NonceLen:])
	wipe(out)
	return reply, keys, nil
}

// ClientHandshake completes the client side of the CREATE_FAST handshake.
// reply is the server's CREATED_FAST payload (y || H(x||y), ReplyLen bytes).
// keyLen is the number of key-material bytes to derive (for a circuit, this
// is the relay-crypto total key length: 72 bytes of relay keys + 20 bytes
// KH). It verifies the integrity check and returns the derived key material
// (keyLen bytes). This mirrors fast_client_handshake (onion_fast.c).
func (s *State) ClientHandshake(reply []byte, keyLen int) ([]byte, error) {
	if len(reply) < ReplyLen {
		return nil, errors.New("fast: short CREATED_FAST reply")
	}
	y := reply[:NonceLen]
	wantHash := reply[NonceLen:ReplyLen]

	// key_in = x || y. out = TAP-Expand(key_in, keyLen + NonceLen). The first
	// NonceLen bytes are the integrity check H(x||y); the remaining keyLen
	// bytes are the key material.
	keyIn := make([]byte, 0, NonceLen*2)
	keyIn = append(keyIn, s.x[:]...)
	keyIn = append(keyIn, y...)
	out := expandTAP(keyIn, keyLen+NonceLen)
	gotHash := out[:NonceLen]
	keys := out[NonceLen:]

	// Constant-time compare of the integrity check.
	if !ctEqual(gotHash, wantHash) {
		return nil, errors.New("fast: CREATED_FAST digest does not match")
	}
	// Return a copy so the caller owns the bytes (out is wiped below).
	res := make([]byte, keyLen)
	copy(res, keys)
	wipe(out)
	return res, nil
}

// expandTAP implements crypto_expand_key_material_TAP (crypto_hkdf.c):
// output = SHA1(key_in || 0) || SHA1(key_in || 1) || ... truncated to n.
func expandTAP(keyIn []byte, n int) []byte {
	out := make([]byte, n)
	buf := make([]byte, len(keyIn)+1)
	copy(buf, keyIn)
	for i, off := 0, 0; off < n; i, off = i+1, off+sha1.Size {
		buf[len(keyIn)] = byte(i)
		h := sha1.Sum(buf)
		end := off + sha1.Size
		if end > n {
			end = n
		}
		copy(out[off:end], h[:end-off])
	}
	return out
}

// ctEqual reports whether a and b are equal in constant time.
func ctEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// wipe zeroizes b.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
