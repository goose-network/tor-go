package ntor

import (
	"bytes"
	"crypto/subtle"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// v3ServerKeyPair is a relay's ntor-v3 identity: its 32-byte Ed25519
// identity public key (ID) and its Curve25519 onion keypair (B).
type v3ServerKeyPair struct {
	EdID   [32]byte
	SecB   [32]byte
	PubB   [32]byte
}

func v3GenerateServerKeyPair(edID [32]byte) (*v3ServerKeyPair, error) {
	kp := &v3ServerKeyPair{EdID: edID}
	if _, err := randRead(kp.SecB[:]); err != nil {
		return nil, err
	}
	kp.SecB[0] &= 248
	kp.SecB[31] &= 127
	kp.SecB[31] |= 64
	pub, err := curve25519.X25519(kp.SecB[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.PubB[:], pub)
	return kp, nil
}

// v3ServerHandshake is an independent server-side implementation of the
// ntor-v3 handshake, mirroring onion_ntor_v3.c. It parses the client
// onionskin, verifies the client's phase-1 MAC, derives the shared keys,
// and produces the Y||AUTH||enc_smsg reply. It is used only to validate the
// client implementation in tests.
func v3ServerHandshake(onionskin []byte, kp *v3ServerKeyPair, keyLen int) (reply []byte, keys []byte, err error) {
	if len(onionskin) < V3OnionskinMinLen {
		return nil, nil, errShortOnionskin
	}
	edID := onionskin[0:32]
	pubB := onionskin[32:64]
	pubX := onionskin[64:96]
	// The encrypted client message is everything between X and the trailing
	// 32-byte MAC.
	encMsg := onionskin[96 : len(onionskin)-32]
	clientMAC := onionskin[len(onionskin)-32:]

	// Phase-1 KDF: absorb = ENCAP(T_MSGKDF) || Bx || ID || X || B || PROTOID || ENCAP(VER)
	bx, err := curve25519.X25519(kp.SecB[:], pubX)
	if err != nil {
		return nil, nil, err
	}
	var absorb []byte
	absorb = encap(absorb, []byte(v3TMsgKDF))
	absorb = append(absorb, bx...)
	absorb = append(absorb, edID...)
	absorb = append(absorb, pubX...)
	absorb = append(absorb, pubB...)
	absorb = append(absorb, []byte(v3ProtoID)...)
	absorb = encap(absorb, []byte(v3Verification))
	phase1 := shake256Squeeze(absorb, 64)
	encKey := phase1[0:32]
	macKey := phase1[32:64]

	// Verify the client's phase-1 MAC.
	var macInput []byte
	macInput = encap(macInput, []byte(v3TMsgMAC))
	macInput = encap(macInput, macKey)
	macInput = append(macInput, edID...)
	macInput = append(macInput, pubB...)
	macInput = append(macInput, pubX...)
	macInput = append(macInput, encMsg...)
	wantMAC := sha3_256Hash(macInput)
	if subtle.ConstantTimeCompare(wantMAC[:], clientMAC) != 1 {
		return nil, nil, errBadClientMAC
	}

	// Decrypt the client message with AES-256-CTR (zero IV), mirroring the
	// real server. We discard the plaintext; the round-trip only needs the
	// keys, but exercising the decrypt path catches key-derivation bugs.
	decMsg := append([]byte(nil), encMsg...)
	aes256Ctr(encKey, decMsg)

	// Generate ephemeral y, Y.
	var secY [32]byte
	if _, err := randRead(secY[:]); err != nil {
		return nil, nil, err
	}
	secY[0] &= 248
	secY[31] &= 127
	secY[31] |= 64
	pubY, err := curve25519.X25519(secY[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	// secret_input = yx || Bx || ID || B || X || Y || PROTOID || ENCAP(VER)
	yx, err := curve25519.X25519(secY[:], pubX)
	if err != nil {
		return nil, nil, err
	}
	var secretInput []byte
	secretInput = append(secretInput, yx...)
	secretInput = append(secretInput, bx...)
	secretInput = append(secretInput, edID...)
	secretInput = append(secretInput, pubB...)
	secretInput = append(secretInput, pubX...)
	secretInput = append(secretInput, pubY...)
	secretInput = append(secretInput, []byte(v3ProtoID)...)
	secretInput = encap(secretInput, []byte(v3Verification))

	// key_seed = SHA3-256( ENCAP(T_KEY_SEED) || secret_input )
	var ksIn []byte
	ksIn = encap(ksIn, []byte(v3TKeySeed))
	ksIn = append(ksIn, secretInput...)
	keySeed := sha3_256Hash(ksIn)

	// verify = SHA3-256( ENCAP(T_VERIFY) || secret_input )
	var vIn []byte
	vIn = encap(vIn, []byte(v3TVerify))
	vIn = append(vIn, secretInput...)
	verify := sha3_256Hash(vIn)

	// Server message: empty (the client accepts an empty server message).
	encSmsg := []byte{}

	// AUTH = SHA3-256( ENCAP(T_AUTH) || verify || ID || B || Y || X || msg_mac
	//                  || ENCAP(enc_smsg) || PROTOID || "Server" )
	var authIn []byte
	authIn = encap(authIn, []byte(v3TAuth))
	authIn = append(authIn, verify[:]...)
	authIn = append(authIn, edID...)
	authIn = append(authIn, pubB...)
	authIn = append(authIn, pubY...)
	authIn = append(authIn, pubX...)
	authIn = append(authIn, wantMAC[:]...) // msg_mac = client's phase-1 MAC
	authIn = encap(authIn, encSmsg)
	authIn = append(authIn, []byte(v3ProtoID)...)
	authIn = append(authIn, []byte(v3ServerStr)...)
	auth := sha3_256Hash(authIn)

	// Final KDF: stream = SHAKE-256( ENCAP(T_FINAL) || key_seed ); squeeze
	// 32 bytes enc_key then keyLen relay keys.
	var finalIn []byte
	finalIn = encap(finalIn, []byte(v3TFinal))
	finalIn = append(finalIn, keySeed[:]...)
	stream := shake256Squeeze(finalIn, 32+keyLen)
	keys = make([]byte, keyLen)
	copy(keys, stream[32:32+keyLen])

	// Reply = Y || AUTH || enc_smsg.
	reply = make([]byte, 0, 64+len(encSmsg))
	reply = append(reply, pubY...)
	reply = append(reply, auth[:]...)
	reply = append(reply, encSmsg...)
	return reply, keys, nil
}

var (
	errShortOnionskin = errV3("ntor: v3 server: onionskin too short")
	errBadClientMAC   = errV3("ntor: v3 server: bad client MAC")
)

// errV3 is a tiny helper to construct distinct errors without importing
// errors in the test (kept self-contained).
type errV3 string

func (e errV3) Error() string { return string(e) }

// TestNtorV3HandshakeRoundTrip verifies the client and an independent server
// implementation derive identical relay-crypto key material.
func TestNtorV3HandshakeRoundTrip(t *testing.T) {
	var edID [32]byte
	for i := range edID {
		edID[i] = byte(i) + 1
	}
	kp, err := v3GenerateServerKeyPair(edID)
	if err != nil {
		t.Fatalf("v3GenerateServerKeyPair: %v", err)
	}

	onionskin, state, err := V3Create(edID[:], kp.PubB[:])
	if err != nil {
		t.Fatalf("V3Create: %v", err)
	}
	if len(onionskin) != V3OnionskinMinLen+len(v3ClientMessage) {
		t.Fatalf("onionskin len = %d, want %d", len(onionskin), V3OnionskinMinLen+len(v3ClientMessage))
	}

	reply, serverKeys, err := v3ServerHandshake(onionskin, kp, V3KeyMaterialLen)
	if err != nil {
		t.Fatalf("v3ServerHandshake: %v", err)
	}
	if len(reply) < V3ReplyMinLen {
		t.Fatalf("reply len = %d, want >= %d", len(reply), V3ReplyMinLen)
	}

	clientKeys, err := state.V3ClientHandshake(reply, V3KeyMaterialLen)
	if err != nil {
		t.Fatalf("V3ClientHandshake: %v", err)
	}
	if !bytes.Equal(clientKeys, serverKeys) {
		t.Fatalf("v3 key mismatch:\n client = %x\n server = %x", clientKeys, serverKeys)
	}
}

// TestNtorV3BadAuth verifies that a tampered server reply (flipped AUTH byte)
// is rejected by the client's AUTH verification.
func TestNtorV3BadAuth(t *testing.T) {
	var edID [32]byte
	for i := range edID {
		edID[i] = byte(i) + 1
	}
	kp, err := v3GenerateServerKeyPair(edID)
	if err != nil {
		t.Fatalf("v3GenerateServerKeyPair: %v", err)
	}
	onionskin, state, err := V3Create(edID[:], kp.PubB[:])
	if err != nil {
		t.Fatalf("V3Create: %v", err)
	}
	reply, _, err := v3ServerHandshake(onionskin, kp, V3KeyMaterialLen)
	if err != nil {
		t.Fatalf("v3ServerHandshake: %v", err)
	}
	// Flip a byte in the AUTH tag (bytes 32:64).
	reply[40] ^= 0xff
	if _, err := state.V3ClientHandshake(reply, V3KeyMaterialLen); err == nil {
		t.Fatal("expected AUTH verification to fail on tampered reply")
	}
}

// TestNtorV3ServerRejectsWrongOnionKey verifies the server's phase-1 MAC
// check rejects an onionskin whose onion key (B) does not match the server's
// advertised key. In ntor v3 the client's MAC binds the onionskin to B, so a
// wrong-key server cannot even produce a reply (unlike v1, which falls back
// to a junk keypair). This validates the server-side integrity check.
func TestNtorV3ServerRejectsWrongOnionKey(t *testing.T) {
	var edID [32]byte
	for i := range edID {
		edID[i] = byte(i) + 1
	}
	kp, err := v3GenerateServerKeyPair(edID)
	if err != nil {
		t.Fatalf("v3GenerateServerKeyPair: %v", err)
	}
	// Client targets a *different* onion key than the server holds.
	var wrongB [32]byte
	for i := range wrongB {
		wrongB[i] = byte(i) + 7
	}
	onionskin, _, err := V3Create(edID[:], wrongB[:])
	if err != nil {
		t.Fatalf("V3Create: %v", err)
	}
	if _, _, err := v3ServerHandshake(onionskin, kp, V3KeyMaterialLen); err == nil {
		t.Fatal("expected server to reject onionskin with wrong onion key")
	}
}

// TestNtorV3ShortReply verifies the client rejects an undersized reply.
func TestNtorV3ShortReply(t *testing.T) {
	var edID [32]byte
	for i := range edID {
		edID[i] = byte(i) + 1
	}
	kp, err := v3GenerateServerKeyPair(edID)
	if err != nil {
		t.Fatalf("v3GenerateServerKeyPair: %v", err)
	}
	_, state, err := V3Create(edID[:], kp.PubB[:])
	if err != nil {
		t.Fatalf("V3Create: %v", err)
	}
	short := make([]byte, V3ReplyMinLen-1)
	if _, err := state.V3ClientHandshake(short, V3KeyMaterialLen); err == nil {
		t.Fatal("expected error for short reply")
	}
}
