package testharness_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/goose-network/tor-go/internal/circuit"
	"github.com/goose-network/tor-go/internal/directory"
	"github.com/goose-network/tor-go/internal/link"
	"github.com/goose-network/tor-go/internal/testharness"
)

// buildDir converts a harness's directory entries into a directory.Router map
// the client packages can use.
func buildDir(h *testharness.Harness) map[string]*directory.Router {
	out := make(map[string]*directory.Router)
	for _, e := range h.AllEntries() {
		r := &directory.Router{}
		r.Nickname = e.Nickname
		r.IDDigest = e.IDDigest
		r.OnionKey = e.OnionKey
		r.Address = e.Address
		r.Flags = e.Flags
		out[fmt.Sprintf("%x", r.IDDigest[:])] = r
	}
	return out
}

// pathFromDir builds a link.RouterIdentity path from the directory in harness
// order (guard, middle, exit).
func pathFromDir(dir map[string]*directory.Router, h *testharness.Harness) []link.RouterIdentity {
	entries := h.AllEntries()
	path := make([]link.RouterIdentity, 0, len(entries))
	for _, e := range entries {
		// Find the matching router by identity digest.
		key := fmt.Sprintf("%x", e.IDDigest[:])
		r := dir[key]
		if r == nil {
			panic("router not found: " + e.Nickname)
		}
		path = append(path, r.RouterIdentity)
	}
	return path
}

// TestLinkHandshake builds a single-hop link to the guard mock relay and
// verifies the v3 link handshake completes (VERSIONS -> CERTS ->
// AUTH_CHALLENGE -> NETINFO).
func TestLinkHandshake(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.GuardEntry()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := link.Dial(ctx, guard.Address, guard.IDDigest[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()
	if l.Protocol() < 4 {
		t.Fatalf("link protocol = %d, want >= 4", l.Protocol())
	}
	t.Logf("link handshake ok: proto=%d guard=%s", l.Protocol(), guard.Address)
}

// TestOneHopCircuit builds a one-hop circuit (CREATE2/CREATED2 + ntor) to the
// guard and verifies the handshake completes.
func TestOneHopCircuit(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.GuardEntry()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	l, err := link.Dial(ctx, guard.Address, guard.IDDigest[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()

	dir := buildDir(h)
	path := pathFromDir(dir, h)
	cctx, ccancel := context.WithTimeout(ctx, 10*time.Second)
	defer ccancel()
	circ, err := circuit.New(cctx, l, path)
	if err != nil {
		t.Fatalf("circuit.New (1 hop): %v", err)
	}
	defer circ.Close()
	if circ.HopCount() != 1 {
		t.Fatalf("hop count = %d, want 1", circ.HopCount())
	}
	t.Logf("one-hop circuit built: circID=%d", circ.CircID())
}

// TestThreeHopCircuit builds a three-hop circuit (guard, middle, exit) using
// CREATE2 for the first hop and EXTEND2/EXTENDED2 for the next two, verifying
// the full multi-hop ntor + relay-crypto path.
func TestThreeHopCircuit(t *testing.T) {
	h, err := testharness.NewHarness(3)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.GuardEntry()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l, err := link.Dial(ctx, guard.Address, guard.IDDigest[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()

	dir := buildDir(h)
	path := pathFromDir(dir, h)
	cctx, ccancel := context.WithTimeout(ctx, 15*time.Second)
	defer ccancel()
	circ, err := circuit.New(cctx, l, path)
	if err != nil {
		t.Fatalf("circuit.New (3 hops): %v", err)
	}
	defer circ.Close()
	if circ.HopCount() != 3 {
		t.Fatalf("hop count = %d, want 3", circ.HopCount())
	}
	t.Logf("three-hop circuit built: circID=%d", circ.CircID())
}

// echoServer starts a TCP echo server on an ephemeral loopback port and
// returns its address. It echoes back any bytes it receives, prefixed with
// "echo: ", until the connection closes.
func echoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // simple echo
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// TestStreamOverOneHop builds a one-hop circuit, opens a stream to a loopback
// echo server, writes data, and reads it back — exercising RELAY_BEGIN,
// RELAY_CONNECTED, RELAY_DATA, and RELAY_END.
func TestStreamOverOneHop(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.GuardEntry()
	echoAddr := echoServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	l, err := link.Dial(ctx, guard.Address, guard.IDDigest[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()

	dir := buildDir(h)
	path := pathFromDir(dir, h)
	circ, err := circuit.New(ctx, l, path)
	if err != nil {
		t.Fatalf("circuit.New: %v", err)
	}
	defer circ.Close()

	stream, err := circ.OpenStream(ctx, echoAddr)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	msg := "hello-tor-go"
	if _, err := stream.Write([]byte(msg)); err != nil {
		t.Fatalf("stream.Write: %v", err)
	}
	data, err := stream.Read()
	if err != nil {
		t.Fatalf("stream.Read: %v", err)
	}
	if string(data) != msg {
		t.Fatalf("echo = %q, want %q", string(data), msg)
	}
	t.Logf("one-hop stream echo ok: %q", string(data))
}

// TestStreamOverThreeHop is like TestStreamOverOneHop but through a full
// three-hop circuit, exercising EXTEND2 and the layered relay crypto for data.
func TestStreamOverThreeHop(t *testing.T) {
	h, err := testharness.NewHarness(3)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.GuardEntry()
	echoAddr := echoServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l, err := link.Dial(ctx, guard.Address, guard.IDDigest[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()

	dir := buildDir(h)
	path := pathFromDir(dir, h)
	circ, err := circuit.New(ctx, l, path)
	if err != nil {
		t.Fatalf("circuit.New: %v", err)
	}
	defer circ.Close()

	stream, err := circ.OpenStream(ctx, echoAddr)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	// Write a few messages and read them back.
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("msg-%d-through-tor", i)
		if _, err := stream.Write([]byte(msg)); err != nil {
			t.Fatalf("stream.Write %d: %v", i, err)
		}
		data, err := stream.Read()
		if err != nil {
			t.Fatalf("stream.Read %d: %v", i, err)
		}
		if string(data) != msg {
			t.Fatalf("echo %d = %q, want %q", i, string(data), msg)
		}
	}
	t.Log("three-hop stream echo ok")
}

// TestStreamRefused verifies that a RELAY_BEGIN to a closed port yields a
// stream error (the exit sends RELAY_END with CONNECTREFUSED).
func TestStreamRefused(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.GuardEntry()

	// Find a closed port: listen and immediately close.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	l, err := link.Dial(ctx, guard.Address, guard.IDDigest[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()

	dir := buildDir(h)
	path := pathFromDir(dir, h)
	circ, err := circuit.New(ctx, l, path)
	if err != nil {
		t.Fatalf("circuit.New: %v", err)
	}
	defer circ.Close()

	_, err = circ.OpenStream(ctx, closedAddr)
	if err == nil {
		t.Fatal("OpenStream to closed port succeeded; want error")
	}
	// The error should mention the stream ended (RELAY_END).
	if !strings.Contains(err.Error(), "ended") && !strings.Contains(err.Error(), "refused") {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("stream to closed port correctly failed: %v", err)
}
