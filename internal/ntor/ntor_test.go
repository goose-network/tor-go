package ntor

import (
	"bytes"
	"testing"
)

func TestNtorHandshakeRoundTrip(t *testing.T) {
	// Generate a server keypair with a known router identity.
	var routerID [20]byte
	copy(routerID[:], []byte("12345678901234567890"))
	kp, err := GenerateServerKeyPair(routerID)
	if err != nil {
		t.Fatalf("GenerateServerKeyPair: %v", err)
	}

	// Client creates the onionskin.
	onionskin, state, err := Create(routerID[:], kp.PubKeyB[:])
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(onionskin) != OnionskinLen {
		t.Fatalf("onionskin len = %d, want %d", len(onionskin), OnionskinLen)
	}

	// Server processes the onionskin and produces a reply + keys.
	reply, serverKeys, err := ServerHandshake(onionskin, kp, TotalKeyLenForTest)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	if len(reply) != ReplyLen {
		t.Fatalf("reply len = %d, want %d", len(reply), ReplyLen)
	}

	// Client completes the handshake and derives keys.
	clientKeys, err := state.ClientHandshake(reply, TotalKeyLenForTest)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}

	// Both sides must derive identical key material.
	if !bytes.Equal(clientKeys, serverKeys) {
		t.Fatalf("key mismatch:\n client = %x\n server = %x", clientKeys, serverKeys)
	}
}

func TestNtorBadServerMAC(t *testing.T) {
	var routerID [20]byte
	copy(routerID[:], []byte("12345678901234567890"))
	kp, err := GenerateServerKeyPair(routerID)
	if err != nil {
		t.Fatalf("GenerateServerKeyPair: %v", err)
	}
	onionskin, state, err := Create(routerID[:], kp.PubKeyB[:])
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	reply, _, err := ServerHandshake(onionskin, kp, TotalKeyLenForTest)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	// Corrupt the MAC (last 32 bytes).
	reply[len(reply)-1] ^= 0xFF
	if _, err := state.ClientHandshake(reply, TotalKeyLenForTest); err == nil {
		t.Fatal("ClientHandshake succeeded with corrupted MAC; want error")
	}
}

func TestNtorWrongOnionKey(t *testing.T) {
	var routerID [20]byte
	copy(routerID[:], []byte("12345678901234567890"))
	kp, err := GenerateServerKeyPair(routerID)
	if err != nil {
		t.Fatalf("GenerateServerKeyPair: %v", err)
	}
	// Client uses a different (wrong) onion key.
	var wrongKey [32]byte
	copy(wrongKey[:], []byte("wrongonionkeywrongonionkeywrong"))
	onionskin, state, err := Create(routerID[:], wrongKey[:])
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Server uses its real keypair; the MAC check at the client must fail
	// because the client computed the expected MAC with the wrong key.
	reply, _, err := ServerHandshake(onionskin, kp, TotalKeyLenForTest)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	if _, err := state.ClientHandshake(reply, TotalKeyLenForTest); err == nil {
		t.Fatal("ClientHandshake succeeded with wrong onion key; want error")
	}
}

// TotalKeyLenForTest is the amount of key material derived in tests (matches
// relaycrypto.TotalKeyLen: 72 key bytes + 20 KH = 92).
const TotalKeyLenForTest = 92
