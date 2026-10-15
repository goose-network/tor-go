package testharness_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/goose-network/tor-go/internal/circuit"
	"github.com/goose-network/tor-go/internal/link"
	"github.com/goose-network/tor-go/internal/testharness"
)

// TestOneHopFastCircuit verifies the CREATE_FAST one-hop circuit path: it
// dials a single mock relay's ORPort over TLS (verifying the relay's identity
// digest), builds a one-hop circuit with circuit.NewOneHopFast (CREATE_FAST /
// CREATED_FAST), opens a BEGIN stream to a loopback origin server, and
// confirms an HTTP request is answered. This exercises the full CREATE_FAST
// cell exchange, the TAP key derivation, relay-crypto layer installation, and
// a relay-cell round trip — the path a real client uses to bootstrap a
// directory fetch from a fallback cache.
func TestOneHopFastCircuit(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.Relays[0]

	// Loopback origin server the exit will dial via BEGIN.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello via fast circuit (path=%s)", r.URL.Path)
	})
	origin := &http.Server{Handler: mux}
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer origin.Close()
	go origin.Serve(originLn)
	originAddr := originLn.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Dial the relay's ORPort over TLS, verifying its identity digest.
	idDigest := guard.IdentityDigest()
	l, err := link.Dial(ctx, guard.Addr(), idDigest[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()

	// Build a one-hop CREATE_FAST circuit.
	circ, err := circuit.NewOneHopFast(ctx, l)
	if err != nil {
		t.Fatalf("NewOneHopFast: %v", err)
	}
	defer circ.Close()
	if circ.HopCount() != 1 {
		t.Fatalf("HopCount = %d, want 1", circ.HopCount())
	}

	// Open a BEGIN stream to the origin through the fast circuit.
	stream, err := circ.OpenStream(ctx, originAddr)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	httpReq := fmt.Sprintf("GET /fast HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originAddr)
	if _, err := stream.Write([]byte(httpReq)); err != nil {
		t.Fatalf("write http request: %v", err)
	}
	body, err := io.ReadAll(streamReader{stream})
	if err != nil {
		t.Fatalf("read http response: %v", err)
	}
	if !strings.Contains(string(body), "hello via fast circuit") {
		t.Fatalf("response body = %q, want the fast-circuit marker", string(body))
	}
	if !strings.Contains(string(body), "path=/fast") {
		t.Fatalf("response body = %q, want path=/fast", string(body))
	}
	t.Logf("fast-circuit HTTP response:\n%s", firstLines(string(body), 3))
}

// streamReader adapts circuit.Stream's Read() ([]byte, error) to an io.Reader
// for io.ReadAll. A normal RELAY_END (circuit.ErrEOF) is translated to io.EOF
// so io.ReadAll returns the accumulated body.
type streamReader struct {
	s *circuit.Stream
}

func (sr streamReader) Read(p []byte) (int, error) {
	data, err := sr.s.Read()
	if err != nil {
		if errors.Is(err, circuit.ErrEOF) {
			return 0, io.EOF
		}
		return 0, err
	}
	n := copy(p, data)
	return n, nil
}
