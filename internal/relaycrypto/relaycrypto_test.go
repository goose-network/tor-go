package relaycrypto

import (
	"bytes"
	"testing"

	"github.com/proxy/tor-go/internal/torcell"
)

func TestNewLayerKeyLayout(t *testing.T) {
	// The key material layout must be exactly 72 bytes (20+20+16+16).
	if KeyMaterialLen != 72 {
		t.Fatalf("KeyMaterialLen = %d, want 72", KeyMaterialLen)
	}
	if KHLen != 20 {
		t.Fatalf("KHLen = %d, want 20", KHLen)
	}
	if TotalKeyLen != 92 {
		t.Fatalf("TotalKeyLen = %d, want 92", TotalKeyLen)
	}
}

func TestLayerEncryptDecryptRoundTrip(t *testing.T) {
	// Model a single hop: a client Layer and a relay Layer (reversed) that
	// share the same key material. The client sends a relay cell forward
	// (EncryptOutbound); the relay receives it (RelayReceiveForward) and
	// must recognize it. The relay sends a cell back (RelaySendBackward);
	// the client receives it (DecryptInbound) and must recognize it.
	keys := make([]byte, KeyMaterialLen)
	for i := range keys {
		keys[i] = byte(i)
	}
	client, err := NewLayer(keys)
	if err != nil {
		t.Fatalf("NewLayer client: %v", err)
	}
	relay, err := NewLayerReversed(keys)
	if err != nil {
		t.Fatalf("NewLayerReversed relay: %v", err)
	}

	// --- Forward path (client -> relay) ---
	original := torcell.BuildRelayCell(torcell.RelayBegin, 7, []byte("example.com:80\x00"))

	payload := make([]byte, len(original))
	copy(payload, original[:])
	client.EncryptOutbound(payload)
	if bytes.Equal(payload, original[:]) {
		t.Fatal("encrypted payload equals cleartext")
	}
	if !relay.RelayReceiveForward(payload) {
		t.Fatal("relay did not recognize the forward cell")
	}
	// The integrity field holds the stamped digest after recognition (the
	// cleartext had it zeroed), so compare command, stream id, and the relay
	// payload body rather than the whole cell.
	rc := torcell.ParseRelayCell(payload)
	if rc.Header.Command != torcell.RelayBegin || rc.Header.StreamID != 7 || string(rc.Payload) != "example.com:80\x00" {
		t.Fatalf("forward parsed cell wrong: cmd=%d stream=%d payload=%q",
			rc.Header.Command, rc.Header.StreamID, string(rc.Payload))
	}

	// --- Backward path (relay -> client) ---
	original2 := torcell.BuildRelayCell(torcell.RelayConnected, 7, []byte("\x04\x01\x02\x03\x00\x50"))

	payload2 := make([]byte, len(original2))
	copy(payload2, original2[:])
	relay.RelaySendBackward(payload2)
	if bytes.Equal(payload2, original2[:]) {
		t.Fatal("backward encrypted payload equals cleartext")
	}
	if !client.DecryptInbound(payload2) {
		t.Fatal("client did not recognize the backward cell")
	}
	rc2 := torcell.ParseRelayCell(payload2)
	if rc2.Header.Command != torcell.RelayConnected || rc2.Header.StreamID != 7 {
		t.Fatalf("backward parsed cell wrong: cmd=%d stream=%d", rc2.Header.Command, rc2.Header.StreamID)
	}
	if !bytes.Equal(rc2.Payload, []byte("\x04\x01\x02\x03\x00\x50")) {
		t.Fatalf("backward payload = %x, want 040102030050", rc2.Payload)
	}
}

func TestLayerWrongHopNotRecognized(t *testing.T) {
	// A cell encrypted by the client for hop A must not be recognized by a
	// relay with different key material.
	keysA := make([]byte, KeyMaterialLen)
	keysB := make([]byte, KeyMaterialLen)
	for i := range keysB {
		keysB[i] = 0xAB
	}
	clientA, _ := NewLayer(keysA)
	relayB, _ := NewLayerReversed(keysB)

	original := torcell.BuildRelayCell(torcell.RelayData, 1, []byte("hello"))
	payload := make([]byte, len(original))
	copy(payload, original[:])
	clientA.EncryptOutbound(payload)
	if relayB.RelayReceiveForward(payload) {
		t.Fatal("relayB recognized a cell encrypted for relayA")
	}
}

func TestVerifyKH(t *testing.T) {
	good := make([]byte, KHLen)
	for i := range good {
		good[i] = byte(i)
	}
	if err := VerifyKH(good, good); err != nil {
		t.Fatalf("VerifyKH matching: %v", err)
	}
	bad := make([]byte, KHLen)
	copy(bad, good)
	bad[0] ^= 0xFF
	if err := VerifyKH(good, bad); err == nil {
		t.Fatal("VerifyKH mismatching succeeded; want error")
	}
}
