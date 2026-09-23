// Package relaycrypto implements the layered encryption and integrity
// protection applied to relay cells as they travel along a circuit.
//
// At the client (origin) side, each hop in the circuit owns a layer of
// crypto: a forward AES-128-CTR cipher and a forward SHA-1 running digest
// used when sending cells toward that hop, and a backward cipher + digest
// used when receiving cells from that hop. Cells are encrypted with every
// layer from the exit hop inward to the guard as they leave the client, and
// decrypted (and authenticated) layer by layer as they return.
//
// This mirrors the "tor1" relay crypto in src/core/crypto/relay_crypto_tor1.c
// and the key layout in src/core/crypto/relay_crypto.c.
package relaycrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash"

	"github.com/proxy/tor-go/internal/torcell"
)

// Key material layout produced by the ntor handshake for a single hop
// (CPATH_KEY_MATERIAL_LEN = 20*2 + 16*2 = 72 bytes), plus a trailing 20-byte
// KH handshake-authenticator digest that the client checks against the
// CREATED2 reply. See src/core/or/or.h (CPATH_KEY_MATERIAL_LEN) and
// src/core/crypto/onion_crypto.c.
const (
	digestLen   = 20 // SHA-1 digest length used for f/b digests and KH
	cipherKeyLen = 16 // AES-128 key length
	// KeyMaterialLen is the number of key bytes consumed by one hop
	// (f_digest || b_digest || f_crypto || b_crypto).
	KeyMaterialLen = digestLen*2 + cipherKeyLen*2
	// KHLen is the trailing handshake-authenticator length.
	KHLen = digestLen
	// TotalKeyLen is the full amount the ntor client handshake must derive
	// for one hop: KeyMaterialLen + KHLen.
	TotalKeyLen = KeyMaterialLen + KHLen
)

// Layer is the crypto state for a single hop on an origin circuit.
type Layer struct {
	// Forward direction (client -> hop): used to encrypt outgoing cells
	// and to set the relay digest.
	fDigest hashState
	fCipher cipher.Stream

	// Backward direction (hop -> client): used to decrypt incoming cells
	// and to verify the relay digest.
	bDigest hashState
	bCipher cipher.Stream
}

// hashState is a running SHA-1 digest that can be copied.
type hashState interface {
	Write([]byte) (int, error)
	Sum(b []byte) []byte
	Reset()
	Clone() hashState
}

// NewLayer initializes a hop's crypto state from key material. The key
// material layout is:
//
//	[0:20]   f_digest seed (SHA-1 initial bytes)
//	[20:40]  b_digest seed
//	[40:56]  f_crypto key (AES-128)
//	[56:72]  b_crypto key (AES-128)
//
// The digest seeds are written into fresh SHA-1 hashes as their initial
// content (matching crypto_digest_add_bytes in the C code).
//
// If reversed is true, the forward and backward keys/digests are swapped.
// The relay side of a hop uses the same key material as the client but with
// reversed roles: the relay's "forward" (toward the client) is the client's
// "backward", and vice versa. This mirrors the `reverse` parameter to
// tor1_crypt_init in the C reference implementation.
func NewLayer(keyMaterial []byte) (*Layer, error) {
	return newLayer(keyMaterial, false)
}

// NewLayerReversed is like NewLayer but swaps the forward and backward
// keys/digests. It is used by the relay side of a hop.
func NewLayerReversed(keyMaterial []byte) (*Layer, error) {
	return newLayer(keyMaterial, true)
}

func newLayer(keyMaterial []byte, reversed bool) (*Layer, error) {
	if len(keyMaterial) < KeyMaterialLen {
		return nil, errors.New("relaycrypto: key material too short")
	}
	l := &Layer{}

	fDigestSeed := keyMaterial[0:digestLen]
	bDigestSeed := keyMaterial[digestLen : 2*digestLen]
	fCipherKey := keyMaterial[2*digestLen : 2*digestLen+cipherKeyLen]
	bCipherKey := keyMaterial[2*digestLen+cipherKeyLen : KeyMaterialLen]
	if reversed {
		fDigestSeed, bDigestSeed = bDigestSeed, fDigestSeed
		fCipherKey, bCipherKey = bCipherKey, fCipherKey
	}

	l.fDigest = newDigest()
	l.fDigest.Write(fDigestSeed)
	l.bDigest = newDigest()
	l.bDigest.Write(bDigestSeed)

	fc, err := aes.NewCipher(fCipherKey)
	if err != nil {
		return nil, err
	}
	bc, err := aes.NewCipher(bCipherKey)
	if err != nil {
		return nil, err
	}
	// Tor uses AES-128-CTR with a zero IV (the cipher is re-keyed per hop,
	// and the CTR counter starts at 0). The stream is advanced continuously
	// across cells.
	l.fCipher = cipher.NewCTR(fc, make([]byte, aes.BlockSize))
	l.bCipher = cipher.NewCTR(bc, make([]byte, aes.BlockSize))
	return l, nil
}

// newDigest returns a cloneable SHA-1 running digest.
func newDigest() hashState {
	return &cloneableDigest{h: sha1.New()}
}

// cloneableDigest implements hashState by wrapping sha1.New and supporting
// clone by keeping a copy of all bytes written so far and re-feeding them on
// clone. This is acceptable for the relay digest because the total bytes
// written is bounded by the number of cells, and clones happen only when we
// tentatively process a cell.
type cloneableDigest struct {
	h       hash.Hash
	written []byte
}

func (d *cloneableDigest) Write(p []byte) (int, error) {
	d.written = append(d.written, p...)
	return d.h.Write(p)
}

func (d *cloneableDigest) Sum(b []byte) []byte { return d.h.Sum(b) }
func (d *cloneableDigest) Reset() {
	d.h.Reset()
	d.written = nil
}

func (d *cloneableDigest) Clone() hashState {
	h := sha1.New()
	h.Write(d.written)
	return &cloneableDigest{h: h, written: append([]byte(nil), d.written...)}
}

// EncryptOutbound encrypts a relay cell payload in the forward direction
// (toward this hop) and stamps the v0 relay digest. The cell payload is
// modified in place. This is used by the origin client when sending a relay
// cell that this hop should process (i.e. it is the outermost not-yet-
// encrypted layer).
//
// The digest is computed over the relay header + payload with the integrity
// field zeroed, then the first 4 bytes of the digest are written into the
// integrity field, and finally the whole payload is AES-CTR encrypted.
func (l *Layer) EncryptOutbound(payload []byte) {
	setRelayDigestV0(l.fDigest, payload)
	l.fCipher.XORKeyStream(payload, payload)
}

// DecryptInbound decrypts a relay cell payload in the backward direction
// (from this hop) and verifies the v0 relay digest. It returns true if the
// digest matches (meaning this cell is destined for us at this layer).
//
// Decryption happens first (outermost backward layer first), then the
// recognized field is checked: if it is zero, the cell is for us and we
// verify the digest.
func (l *Layer) DecryptInbound(payload []byte) bool {
	l.bCipher.XORKeyStream(payload, payload)
	return relayDigestMatchesV0(l.bDigest, payload)
}

// EncryptForwardOnly encrypts a relay cell payload in the forward direction
// without stamping a digest. This is used for the layers between the client
// and the target hop: those layers just pass the (already-digested, already-
// encrypted-by-inner-layers) cell through, adding only their AES-CTR layer.
func (l *Layer) EncryptForwardOnly(payload []byte) {
	l.fCipher.XORKeyStream(payload, payload)
}

// DecryptBackwardOnly decrypts a relay cell payload in the backward
// direction without checking the digest. Used for layers above the one the
// cell is destined for.
func (l *Layer) DecryptBackwardOnly(payload []byte) {
	l.bCipher.XORKeyStream(payload, payload)
}

// RelayReceiveForward decrypts a cell arriving in the forward direction
// (from the client toward this relay) and verifies the digest. Used by the
// relay side: the relay's backward layer corresponds to the client's forward
// layer (because NewLayerReversed swaps them). Returns true if the cell is
// recognized (i.e. this relay is the intended hop).
func (l *Layer) RelayReceiveForward(payload []byte) bool {
	// On the relay side (reversed), the "backward" cipher/digest are the
	// ones keyed with the client's forward key material, so we use the
	// backward operations to peel what the client encrypted forward.
	l.bCipher.XORKeyStream(payload, payload)
	return relayDigestMatchesV0(l.bDigest, payload)
}

// RelaySendBackward encrypts a cell for the return path (relay -> client)
// and stamps the digest. Used by the relay side: the relay's forward layer
// corresponds to the client's backward layer.
func (l *Layer) RelaySendBackward(payload []byte) {
	setRelayDigestV0(l.fDigest, payload)
	l.fCipher.XORKeyStream(payload, payload)
}

// RelaySendBackwardOnly applies only the backward AES layer (no digest
// stamping) on the relay side. It is used by intermediate hops in the return
// path: the originating (exit) hop stamps the digest with RelaySendBackward,
// and each hop closer to the client adds its AES layer with this method. This
// mirrors the client's DecryptBackwardOnly but in the relay-side direction.
func (l *Layer) RelaySendBackwardOnly(payload []byte) {
	l.fCipher.XORKeyStream(payload, payload)
}

// setRelayDigestV0 stamps the 4-byte v0 relay digest into the integrity
// field of the relay cell payload. The digest is a running SHA-1 over the
// cell payload with the integrity field zeroed; only the first 4 bytes are
// stored. See tor1_set_digest_v0 in relay_crypto_tor1.c.
func setRelayDigestV0(d hashState, payload []byte) {
	// Zero the integrity field.
	zero := [4]byte{}
	copy(payload[torcell.RelayDigestOffset:torcell.RelayDigestOffset+4], zero[:])
	// Update the running digest with the whole payload (header + body).
	d.Write(payload)
	// Compute the current digest and store its first 4 bytes.
	sum := d.Sum(nil)
	copy(payload[torcell.RelayDigestOffset:torcell.RelayDigestOffset+4], sum[:4])
}

// relayDigestMatchesV0 checks whether the 4-byte v0 relay digest in the
// integrity field matches the running digest. It temporarily zeros the
// field, updates the digest, compares, and on mismatch restores the field
// (so the caller can continue decrypting further layers). See
// tor1_relay_digest_matches_v0.
func relayDigestMatchesV0(d hashState, payload []byte) bool {
	received := [4]byte{}
	copy(received[:], payload[torcell.RelayDigestOffset:torcell.RelayDigestOffset+4])
	zero := [4]byte{}
	copy(payload[torcell.RelayDigestOffset:torcell.RelayDigestOffset+4], zero[:])

	// Clone the digest so a failed match does not corrupt the running state.
	clone := d.Clone()
	clone.Write(payload)
	sum := clone.Sum(nil)

	if equal4(received[:], sum[:4]) {
		// Match: commit the digest update to the real state and restore the
		// received integrity bytes (they will be ignored by upper layers).
		d.Write(payload)
		copy(payload[torcell.RelayDigestOffset:torcell.RelayDigestOffset+4], received[:])
		return true
	}
	// Mismatch: restore the received bytes; the running digest is unchanged.
	copy(payload[torcell.RelayDigestOffset:torcell.RelayDigestOffset+4], received[:])
	return false
}

func equal4(a, b []byte) bool {
	var diff byte
	for i := 0; i < 4; i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// VerifyKH compares a 20-byte KH value derived from the handshake against the
// KH carried in the server's CREATED2 reply. Returns nil if they match.
func VerifyKH(expected, reply []byte) error {
	if len(expected) != KHLen || len(reply) < KHLen {
		return errors.New("relaycrypto: bad KH length")
	}
	var diff byte
	for i := 0; i < KHLen; i++ {
		diff |= expected[i] ^ reply[i]
	}
	if diff != 0 {
		return errors.New("relaycrypto: KH mismatch")
	}
	return nil
}

// EncodeRelayEndReason is a small helper kept here to avoid a circular
// import; it writes a 1-byte end reason into a buffer.
func EncodeRelayEndReason(reason uint8) []byte {
	return []byte{reason}
}

// DecodeRelayEndReason reads a 1-byte end reason.
func DecodeRelayEndReason(b []byte) (uint8, error) {
	if len(b) < 1 {
		return 0, errors.New("relaycrypto: empty end reason")
	}
	return b[0], nil
}

// EncodeUint16 writes a big-endian uint16.
func EncodeUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
