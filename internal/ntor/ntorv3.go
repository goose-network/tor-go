// This file implements the ntor v3 circuit-extension handshake
// (ntor3-curve25519-sha3_256-1, proposal 332), used by Tor to establish
// per-hop keys on a circuit with encrypted, authenticated parameter
// negotiation in both directions. It mirrors src/core/crypto/onion_ntor_v3.c
// in the C reference implementation.
//
// Differences from the ntor v1 handshake (ntor.go):
//   - Handshake type is 0x0003 (ONION_HANDSHAKE_TYPE_NTOR_V3).
//   - The relay's Ed25519 identity key (ID) is an input, in addition to its
//     Curve25519 ntor onion key (B).
//   - All hashing uses SHA3-256; the key-derivation expansions use SHAKE-256
//     as an XOF (v1 uses HKDF-SHA-256).
//   - A verification string ("circuit extend") is a mandatory shared input
//     to every hash and the XOF.
//   - The client sends an encrypted, MAC'd message in the onionskin; the
//     server replies with an encrypted, authenticated message. Both messages
//     are AES-256-CTR (zero IV) ciphertexts authenticated by a SHA3-256 tag.
//   - Variable-length inputs to the hashes/XOF are length-prefixed with an
//     8-byte big-endian length (ENCAP); fixed-length fields and the PROTOID
//     string are added raw.
package ntor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

// v3 protocol identifier and tweak strings (onion_ntor_v3.c:37-45).
const (
	v3ProtoID = "ntor3-curve25519-sha3_256-1"

	v3TMsgKDF   = v3ProtoID + ":kdf_phase1"
	v3TMsgMAC   = v3ProtoID + ":msg_mac"
	v3TKeySeed  = v3ProtoID + ":key_seed"
	v3TVerify   = v3ProtoID + ":verify"
	v3TFinal    = v3ProtoID + ":kdf_final"
	v3TAuth     = v3ProtoID + ":auth_final"
	v3ServerStr = "Server"

	// v3Verification is the shared verification string for circuit extends
	// (onion_crypto.c:59-60). It is 14 bytes, no NUL terminator.
	v3Verification = "circuit extend"
)

// Handshake type identifiers (or.h:901-902).
const (
	HandshakeTypeNtor    = 0x0002
	HandshakeTypeNtorV3  = 0x0003
)

// V3OnionskinLen is the length of a minimal ntor-v3 client onionskin with an
// empty client message: ID(32) || B(32) || X(32) || enc_msg(0) || MAC(32)
// = 128 bytes. With a non-empty message it grows by the message length.
const V3OnionskinMinLen = 128

// V3ReplyMinLen is the minimum length of an ntor-v3 server reply with an
// empty server message: Y(32) || AUTH(32) = 64 bytes.
const V3ReplyMinLen = 64

// V3KeyMaterialLen is the number of relay-crypto key bytes the final KDF
// must produce for one hop: 72 bytes of relay key material + 20 bytes of
// rend-circ nonce (KH), matching CPATH_KEY_MATERIAL_LEN + DIGEST_LEN. The
// final SHAKE-256 squeeze also yields a leading 32-byte server-message
// encryption key before this material.
const V3KeyMaterialLen = 92

// v3ClientMessage is the trunnel-encoded client->server negotiation message.
// A real Tor client encodes a trn_extension carrying congestion-control and
// CGO requests. The minimal valid encoding is an empty extension: a 2-byte
// big-endian field count of zero (0x0000). This is the safest interop choice
// for a client that does not negotiate congestion control.
var v3ClientMessage = []byte{0x00, 0x00}

// V3ClientState holds the client-side state between sending an ntor-v3
// onionskin and receiving the server reply.
type V3ClientState struct {
	edID    [32]byte // relay Ed25519 identity public key (ID)
	pubkeyB [32]byte // relay Curve25519 ntor onion public key (B)
	seckeyX [32]byte // client ephemeral Curve25519 secret key
	pubkeyX [32]byte // client ephemeral Curve25519 public key
	msgMAC  [32]byte // phase-1 MAC the client computed (reused in AUTH check)
	encMsg  []byte   // encrypted client message (kept for the AUTH check)
}

// encap appends an 8-byte big-endian length prefix followed by data to dst.
func encap(dst, data []byte) []byte {
	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(data)))
	dst = append(dst, lenbuf[:]...)
	return append(dst, data...)
}

// shake256Squeeze runs SHAKE-256 over the given absorbed input and squeezes
// n bytes. The absorb input is provided as a pre-assembled byte slice.
func shake256Squeeze(input []byte, n int) []byte {
	h := sha3.NewShake256()
	h.Write(input)
	out := make([]byte, n)
	h.Read(out)
	return out
}

// sha3_256Hash computes the canonical SHA3-256 (NIST FIPS 202) over data.
// golang.org/x/crypto/sha3.New256 wraps crypto/sha3.New256.
func sha3_256Hash(data []byte) [32]byte {
	h := sha3.New256()
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// aes256Ctr encrypts (or decrypts) data in place with AES-256-CTR using a
// zero IV and a 128-bit counter, matching Tor's crypto_cipher_new_with_bits
// (IV zero-filled, NSS CKM_AES_CTR with ulCounterBits=128).
func aes256Ctr(key, data []byte) {
	if len(data) == 0 {
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("ntor: aes256Ctr: " + err.Error())
	}
	iv := make([]byte, aes.BlockSize) // all-zero IV
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data)
}

// V3Create performs the first client-side step of the ntor-v3 handshake for a
// server whose 32-byte Ed25519 identity key is edID and whose Curve25519
// onion key is routerKey. It returns the onionskin (ID||B||X||enc_msg||MAC)
// and the opaque client state needed to complete the handshake.
func V3Create(edID, routerKey []byte) (onionskin []byte, state *V3ClientState, err error) {
	if len(edID) != 32 {
		return nil, nil, errors.New("ntor: v3 edID must be 32 bytes")
	}
	if len(routerKey) != 32 {
		return nil, nil, errors.New("ntor: v3 routerKey must be 32 bytes")
	}

	state = &V3ClientState{}
	copy(state.edID[:], edID)
	copy(state.pubkeyB[:], routerKey)

	// Generate an ephemeral Curve25519 keypair (clamped per RFC 7748).
	if _, err := randRead(state.seckeyX[:]); err != nil {
		return nil, nil, err
	}
	state.seckeyX[0] &= 248
	state.seckeyX[31] &= 127
	state.seckeyX[31] |= 64
	pubX, err := curve25519.X25519(state.seckeyX[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	copy(state.pubkeyX[:], pubX)

	// Phase-1 key derivation via SHAKE-256:
	//   absorb = ENCAP(T_MSGKDF) || Bx || ID || X || B || PROTOID || ENCAP(VER)
	//   squeeze 32 bytes enc_key, then 32 bytes mac_key.
	bx, err := curve25519.X25519(state.seckeyX[:], state.pubkeyB[:])
	if err != nil {
		return nil, nil, err
	}
	if isZero(bx) {
		return nil, nil, errors.New("ntor: v3 zero output from curve25519 (bad onion key)")
	}
	var absorb []byte
	absorb = encap(absorb, []byte(v3TMsgKDF))
	absorb = append(absorb, bx...)            // Bx (raw)
	absorb = append(absorb, state.edID[:]...) // ID (raw)
	absorb = append(absorb, state.pubkeyX[:]...) // X (raw)
	absorb = append(absorb, state.pubkeyB[:]...) // B (raw)
	absorb = append(absorb, []byte(v3ProtoID)...) // PROTOID (raw)
	absorb = encap(absorb, []byte(v3Verification)) // ENCAP(VER)
	phase1 := shake256Squeeze(absorb, 64) // enc_key(32) || mac_key(32)
	encKey := phase1[0:32]
	macKey := phase1[32:64]

	// Encrypt the client message with AES-256-CTR (zero IV).
	msg := append([]byte(nil), v3ClientMessage...)
	aes256Ctr(encKey, msg)
	state.encMsg = msg

	// Client MAC = SHA3-256( ENCAP(T_MSGMAC) || ENCAP(mac_key) || ID || B || X || enc_msg )
	var macInput []byte
	macInput = encap(macInput, []byte(v3TMsgMAC))
	macInput = encap(macInput, macKey)
	macInput = append(macInput, state.edID[:]...)
	macInput = append(macInput, state.pubkeyB[:]...)
	macInput = append(macInput, state.pubkeyX[:]...)
	macInput = append(macInput, msg...)
	state.msgMAC = sha3_256Hash(macInput)

	// Assemble the onionskin: ID || B || X || enc_msg || MAC.
	onionskin = make([]byte, 0, 96+len(msg)+32)
	onionskin = append(onionskin, state.edID[:]...)
	onionskin = append(onionskin, state.pubkeyB[:]...)
	onionskin = append(onionskin, state.pubkeyX[:]...)
	onionskin = append(onionskin, msg...)
	onionskin = append(onionskin, state.msgMAC[:]...)
	return onionskin, state, nil
}

// V3ClientHandshake performs the final client-side step. Given the state from
// V3Create and the server's reply (Y || AUTH || enc_smsg), it verifies the
// AUTH tag and derives keyLen bytes of key material (relay-crypto keys + KH).
// It returns an error if authentication fails.
func (s *V3ClientState) V3ClientHandshake(reply []byte, keyLen int) (keys []byte, err error) {
	if len(reply) < V3ReplyMinLen {
		return nil, errors.New("ntor: v3 reply too short")
	}
	var pubkeyY [32]byte
	copy(pubkeyY[:], reply[0:32])
	relayAuth := reply[32:64]
	encSmsg := reply[64:]

	// Compute the two DH shared secrets: yx = EXP(X,Y) and Bx = EXP(X,B).
	yx, err := curve25519.X25519(s.seckeyX[:], pubkeyY[:])
	if err != nil {
		return nil, err
	}
	if isZero(yx) {
		return nil, errors.New("ntor: v3 zero output from curve25519 (bad Y)")
	}
	bx, err := curve25519.X25519(s.seckeyX[:], s.pubkeyB[:])
	if err != nil {
		return nil, err
	}

	// secret_input = yx || Bx || ID || B || X || Y || PROTOID || ENCAP(VER)
	var secretInput []byte
	secretInput = append(secretInput, yx...)
	secretInput = append(secretInput, bx...)
	secretInput = append(secretInput, s.edID[:]...)
	secretInput = append(secretInput, s.pubkeyB[:]...)
	secretInput = append(secretInput, s.pubkeyX[:]...)
	secretInput = append(secretInput, pubkeyY[:]...)
	secretInput = append(secretInput, []byte(v3ProtoID)...)
	secretInput = encap(secretInput, []byte(v3Verification))

	// key_seed = SHA3-256( ENCAP(T_KEY_SEED) || secret_input )
	var ksInput []byte
	ksInput = encap(ksInput, []byte(v3TKeySeed))
	ksInput = append(ksInput, secretInput...)
	keySeed := sha3_256Hash(ksInput)

	// verify = SHA3-256( ENCAP(T_VERIFY) || secret_input )
	var vInput []byte
	vInput = encap(vInput, []byte(v3TVerify))
	vInput = append(vInput, secretInput...)
	verify := sha3_256Hash(vInput)

	// AUTH = SHA3-256( ENCAP(T_AUTH) || verify || ID || B || Y || X || msg_mac
	//                    || ENCAP(enc_smsg) || PROTOID || "Server" )
	var authInput []byte
	authInput = encap(authInput, []byte(v3TAuth))
	authInput = append(authInput, verify[:]...)
	authInput = append(authInput, s.edID[:]...)
	authInput = append(authInput, s.pubkeyB[:]...)
	authInput = append(authInput, pubkeyY[:]...)
	authInput = append(authInput, s.pubkeyX[:]...)
	authInput = append(authInput, s.msgMAC[:]...)
	authInput = encap(authInput, encSmsg)
	authInput = append(authInput, []byte(v3ProtoID)...)
	authInput = append(authInput, []byte(v3ServerStr)...)
	authComputed := sha3_256Hash(authInput)

	// Constant-time compare against the server's AUTH tag.
	if subtle.ConstantTimeCompare(authComputed[:], relayAuth) != 1 {
		return nil, errors.New("ntor: v3 bad server AUTH (wrong identity/onion key or tampered reply)")
	}

	// Final KDF via SHAKE-256:
	//   stream = SHAKE-256( ENCAP(T_FINAL) || key_seed )
	//   squeeze 32 bytes enc_key (server-message key), then keyLen relay keys.
	var finalInput []byte
	finalInput = encap(finalInput, []byte(v3TFinal))
	finalInput = append(finalInput, keySeed[:]...)
	stream := shake256Squeeze(finalInput, 32+keyLen)
	keys = make([]byte, keyLen)
	copy(keys, stream[32:32+keyLen])
	return keys, nil
}
