package torclient

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/goose-network/tor-go/internal/circuit"
	"github.com/goose-network/tor-go/internal/link"
	"github.com/goose-network/tor-go/internal/testharness"
)

// TestStreamWrapReadPreservesResidual verifies that streamWrap.Read does not
// drop the bytes of a DATA cell that exceed the caller's buffer. A relay DATA
// payload can be larger than a small read buffer; the old copy(p, data) alone
// silently discarded the tail, corrupting the stream. Reading a multi-cell body
// through a tiny buffer must reassemble every byte, and a normal RELAY_END must
// surface as io.EOF (not the circuit sentinel) so io.Reader consumers finish
// cleanly.
func TestStreamWrapReadPreservesResidual(t *testing.T) {
	h, err := testharness.NewHarness(1)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	guard := h.Relays[0]

	// A body far larger than one relay cell (and than the read buffer below).
	body := bytes.Repeat([]byte("0123456789abcdef"), 400) // 6400 bytes
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
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
	id := guard.IdentityDigest()
	l, err := link.Dial(ctx, guard.Addr(), id[:])
	if err != nil {
		t.Fatalf("link.Dial: %v", err)
	}
	defer l.Close()
	circ, err := circuit.NewOneHopFast(ctx, l)
	if err != nil {
		t.Fatalf("NewOneHopFast: %v", err)
	}
	defer circ.Close()
	stream, err := circ.OpenStream(ctx, originAddr)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	sw := &streamWrap{stream: stream, circ: circ}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originAddr)
	if _, err := sw.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read through a tiny buffer to force the residual path on every cell.
	var got bytes.Buffer
	p := make([]byte, 64)
	for {
		n, rerr := sw.Read(p)
		if n > 0 {
			got.Write(p[:n])
		}
		if rerr != nil {
			// io.EOF (translated from circuit.ErrEOF) is the clean end; anything
			// else is a failure.
			if rerr.Error() != "EOF" {
				t.Fatalf("read response: %v", rerr)
			}
			break
		}
	}
	if !bytes.Contains(got.Bytes(), body) {
		t.Fatalf("response body truncated/corrupted: got %d bytes, want the full %d-byte body present", got.Len(), len(body))
	}
}

// TestIsLinkSuspect verifies the classification that drives strike-counting:
// only FIRST-HOP (guard) timeouts and guard-link death implicate the link itself
// and accrue a strike toward a redial. Later-hop extend timeouts, stream-connect
// timeouts, and caller-budget expiry implicate a bad middle/exit relay or the
// destination — the circuit build already proved the guard alive — so they retry
// a fresh path WITHOUT striking (a strike would redial a healthy guard and sever
// unrelated in-flight streams). A first-hop DESTROY/crypto error is a bad guard
// identity (prop271 failover), not a dead link.
func TestIsLinkSuspect(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"link died", circuit.ErrLinkDied, true},
		{"wrapped link died", fmt.Errorf("build: %w", circuit.ErrLinkDied), true},
		{"circuit closed (live-link teardown, bad relay)", circuit.ErrCircuitClosed, false},
		{"wrapped circuit closed", fmt.Errorf("open stream: %w", circuit.ErrCircuitClosed), false},
		{"first hop cell timeout", fmt.Errorf("circuit: first hop: circuit: timeout waiting for cell 7"), true},
		{"first hop deadline", fmt.Errorf("circuit: first hop: %w", context.DeadlineExceeded), true},
		{"fast first hop timeout", fmt.Errorf("circuit: fast first hop: circuit: timeout waiting for cell 7"), true},
		{"bare deadline (no stage)", context.DeadlineExceeded, false},
		{"extend hop timeout (bad middle)", fmt.Errorf("circuit: hop 2: circuit: timeout waiting for relay 6"), false},
		{"stream connect timeout (bad exit/dest)", fmt.Errorf("circuit: stream connect timeout"), false},
		{"first hop destroy (bad guard identity)", fmt.Errorf("circuit: first hop: circuit: destroyed (reason 6)"), false},
		{"destroy (bad relay)", fmt.Errorf("circuit: destroyed (reason 6)"), false},
		{"crypto (bad relay)", fmt.Errorf("circuit: relay cell not recognized by any hop"), false},
		{"ntor (bad relay)", fmt.Errorf("ntor: handshake verification failed"), false},
		{"canceled", context.Canceled, false},
	}
	for _, c := range cases {
		if got := isLinkSuspect(c.err); got != c.want {
			t.Errorf("%s: isLinkSuspect(%v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}
