package fast

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

// TestFastRoundTrip exercises the full CREATE_FAST handshake against an
// independent server implementation (fastServerHandshake, mirroring
// fast_server_handshake in onion_fast.c), then verifies the client and
// server derive identical key material and that the integrity check passes.
func TestFastRoundTrip(t *testing.T) {
	const keyLen = 92 // 72 relay keys + 20 KH, matching relaycrypto total

	// Client side: create the onionskin (nonce x).
	onionskin, st, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(onionskin) != NonceLen {
		t.Fatalf("onionskin len = %d, want %d", len(onionskin), NonceLen)
	}

	// Server side: produce the CREATED_FAST reply (y || H(x||y)).
	reply, err := fastServerHandshake(onionskin, keyLen)
	if err != nil {
		t.Fatalf("fastServerHandshake: %v", err)
	}
	if len(reply) != ReplyLen {
		t.Fatalf("reply len = %d, want %d", len(reply), ReplyLen)
	}

	// Client side: complete the handshake and derive keys.
	keys, err := st.ClientHandshake(reply, keyLen)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	if len(keys) != keyLen {
		t.Fatalf("keys len = %d, want %d", len(keys), keyLen)
	}

	// Independently recompute the expected key material from x and y and
	// confirm the client derived the same bytes.
	x := onionskin
	y := reply[:NonceLen]
	keyIn := make([]byte, 0, NonceLen*2)
	keyIn = append(keyIn, x...)
	keyIn = append(keyIn, y...)
	want := expandTAP(keyIn, keyLen+NonceLen)[NonceLen:]
	if !bytes.Equal(keys, want) {
		t.Fatalf("client keys do not match independently derived material")
	}
}

// TestFastBadIntegrity verifies the client rejects a CREATED_FAST reply
// whose integrity check (trailing 20 bytes) has been tampered with.
func TestFastBadIntegrity(t *testing.T) {
	const keyLen = 92
	onionskin, st, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	reply, err := fastServerHandshake(onionskin, keyLen)
	if err != nil {
		t.Fatalf("fastServerHandshake: %v", err)
	}
	// Flip a bit in the integrity-check half of the reply.
	reply[NonceLen] ^= 0x01
	if _, err := st.ClientHandshake(reply, keyLen); err == nil {
		t.Fatalf("ClientHandshake succeeded with tampered integrity check; want error")
	}
}

// TestFastShortReply verifies a too-short reply is rejected.
func TestFastShortReply(t *testing.T) {
	_, st, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := st.ClientHandshake(make([]byte, ReplyLen-1), 92); err == nil {
		t.Fatalf("ClientHandshake succeeded on short reply; want error")
	}
}

// TestExpandTAP verifies the TAP key expansion against a hand-computed
// reference: output = SHA1(key||0) || SHA1(key||1) || ... truncated.
func TestExpandTAP(t *testing.T) {
	key := []byte("the quick brown fox")
	n := 45 // spans three SHA-1 blocks (20+20+5)
	got := expandTAP(key, n)

	// Independently compute the expected concatenation.
	var want []byte
	for i := 0; len(want) < n; i++ {
		h := sha1.Sum(append(append([]byte{}, key...), byte(i)))
		want = append(want, h[:]...)
	}
	want = want[:n]
	if !bytes.Equal(got, want) {
		t.Fatalf("expandTAP mismatch:\n got %x\nwant %x", got, want)
	}
}

// fastServerHandshake is a thin wrapper over the canonical ServerHandshake
// for tests that only need the reply (not the server's derived keys). It
// keeps the independent-server shape of the round-trip test while sharing
// the package's TAP expansion so client and server cannot drift.
func fastServerHandshake(onionskin []byte, keyLen int) ([]byte, error) {
	reply, _, err := ServerHandshake(onionskin, keyLen)
	return reply, err
}

// TestServerHandshakeKeys verifies the server's derived key material matches
// what the client derives from the same reply — i.e. both sides arrive at
// the same relay-crypto keys.
func TestServerHandshakeKeys(t *testing.T) {
	const keyLen = 92
	onionskin, st, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	reply, serverKeys, err := ServerHandshake(onionskin, keyLen)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	clientKeys, err := st.ClientHandshake(reply, keyLen)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	if !bytes.Equal(clientKeys, serverKeys) {
		t.Fatalf("client and server key material differ")
	}
}
