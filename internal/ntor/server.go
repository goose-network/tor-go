package ntor

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ServerKeyPair is a relay's identity + onion keypair: the 20-byte identity
// digest and the Curve25519 onion keypair (secret + public). The public key
// is what's advertised in the microdescriptor; the secret key is held by the
// relay.
type ServerKeyPair struct {
	RouterID  [digestLen]byte
	SecKeyB   [pubKeyLen]byte // onion secret key
	PubKeyB   [pubKeyLen]byte // onion public key (advertised)
}

// GenerateServerKeyPair creates a fresh server keypair with the given
// 20-byte router identity digest.
func GenerateServerKeyPair(routerID [digestLen]byte) (*ServerKeyPair, error) {
	kp := &ServerKeyPair{RouterID: routerID}
	if _, err := randRead(kp.SecKeyB[:]); err != nil {
		return nil, err
	}
	kp.SecKeyB[0] &= 248
	kp.SecKeyB[31] &= 127
	kp.SecKeyB[31] |= 64
	pub, err := curve25519.X25519(kp.SecKeyB[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.PubKeyB[:], pub)
	return kp, nil
}

// ServerHandshake performs the server side of the ntor handshake. Given the
// 84-byte onionskin, the server's keypair, and the server's identity digest,
// it produces the 64-byte reply and derives keyLen bytes of key material.
//
// If the onionskin's router ID does not match, it returns an error. If the
// onionskin's onion key does not match the server's advertised key, the
// server proceeds with a junk keypair (so the handshake completes server-
// side without leaking whether the key was recognized, matching Tor's
// behavior); the client's MAC verification will then fail.
//
// This is the counterpart to ClientState.ClientHandshake and is used by the
// mock relay in integration tests. It mirrors onion_skin_ntor_server_handshake
// in src/core/crypto/onion_ntor.c.
func ServerHandshake(onionskin []byte, kp *ServerKeyPair, keyLen int) (reply []byte, keys []byte, err error) {
	if len(onionskin) != OnionskinLen {
		return nil, nil, errors.New("ntor: onionskin must be 84 bytes")
	}
	// Decode the onionskin: routerID || pubkeyB || pubkeyX.
	if !hmac.Equal(onionskin[:digestLen], kp.RouterID[:]) {
		return nil, nil, errors.New("ntor: server: router ID mismatch")
	}
	// Use the real keypair if the onion key matches; otherwise use a junk
	// keypair so we complete the handshake without leaking key recognition.
	useKP := kp
	if !hmac.Equal(onionskin[digestLen:digestLen+pubKeyLen], kp.PubKeyB[:]) {
		junk, jerr := GenerateServerKeyPair(kp.RouterID)
		if jerr != nil {
			return nil, nil, jerr
		}
		useKP = junk
	}
	var pubkeyX [pubKeyLen]byte
	copy(pubkeyX[:], onionskin[digestLen+pubKeyLen:])

	// Generate ephemeral y, Y.
	var seckeyY [pubKeyLen]byte
	if _, err := randRead(seckeyY[:]); err != nil {
		return nil, nil, err
	}
	seckeyY[0] &= 248
	seckeyY[31] &= 127
	seckeyY[31] |= 64
	pubY, err := curve25519.X25519(seckeyY[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	var pubkeyY [pubKeyLen]byte
	copy(pubkeyY[:], pubY)

	// EXP(Y,x) and EXP(B,x).
	yx, err := curve25519.X25519(seckeyY[:], pubkeyX[:])
	if err != nil {
		return nil, nil, err
	}
	bx, err := curve25519.X25519(useKP.SecKeyB[:], pubkeyX[:])
	if err != nil {
		return nil, nil, err
	}
	if isZero(yx) || isZero(bx) {
		return nil, nil, errors.New("ntor: server: zero DH output")
	}

	// secret_input = EXP(Y,x) || EXP(B,x) || B || X || Y || PROTOID
	secretInput := make([]byte, 0, outputLen*2+digestLen+pubKeyLen*3+len(PROTOID))
	secretInput = append(secretInput, yx...)
	secretInput = append(secretInput, bx...)
	secretInput = append(secretInput, useKP.RouterID[:]...)
	secretInput = append(secretInput, useKP.PubKeyB[:]...)
	secretInput = append(secretInput, pubkeyX[:]...)
	secretInput = append(secretInput, pubkeyY[:]...)
	secretInput = append(secretInput, []byte(PROTOID)...)

	// verify = H_tweak(secret_input, t_verify)
	var verify [32]byte
	hTweak(&verify, secretInput, tVerify)

	// auth_input = verify || B || Y || X || PROTOID || "Server"
	authInput := make([]byte, 0, 32+digestLen+pubKeyLen*3+len(PROTOID)+len(serverStr))
	authInput = append(authInput, verify[:]...)
	authInput = append(authInput, useKP.RouterID[:]...)
	authInput = append(authInput, useKP.PubKeyB[:]...)
	authInput = append(authInput, pubkeyY[:]...)
	authInput = append(authInput, pubkeyX[:]...)
	authInput = append(authInput, []byte(PROTOID)...)
	authInput = append(authInput, []byte(serverStr)...)

	// reply = Y || H_tweak(auth_input, t_mac)
	reply = make([]byte, ReplyLen)
	copy(reply[0:pubKeyLen], pubkeyY[:])
	var mac [32]byte
	hTweak(&mac, authInput, tMac)
	copy(reply[pubKeyLen:], mac[:])

	// keys = HKDF(secret_input, salt=t_key, info=t_expand, L=keyLen)
	keys = make([]byte, keyLen)
	h := hkdf.New(sha256.New, secretInput, []byte(tKey), []byte(tExpand))
	if _, err := h.Read(keys); err != nil {
		return nil, nil, err
	}
	return reply, keys, nil
}

// hmacSHA256 is a small helper kept for clarity in the server path.
func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
