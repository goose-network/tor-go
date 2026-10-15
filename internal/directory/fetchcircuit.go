package directory

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/goose-network/tor-go/internal/circuit"
	"github.com/goose-network/tor-go/internal/fallback"
	"github.com/goose-network/tor-go/internal/link"
)

// fetchViaFallbackCircuit bootstraps the microconsensus and microdescriptors
// over a one-hop CREATE_FAST circuit to a fallback directory cache, mirroring
// the C client's directory_fetch_from_dirserver / BEGIN_DIR path
// (dirclient.c). It tries each fallback in DefaultFallbacks in order: for
// each, it dials the fallback's ORPort over TLS (verifying the relay's RSA
// identity digest against the hardcoded fingerprint), builds a one-hop fast
// circuit, opens a BEGIN_DIR stream, and fetches the consensus and
// microdescriptors as plain HTTP/1.1 over the stream. The first fallback that
// yields a usable consensus wins; microdescriptors are fetched from the same
// fallback.
//
// The directory protocol over BEGIN_DIR is HTTP/1.1 to the relay's directory
// port (which BEGIN_DIR reaches internally): GET /tor/status-vote/current/
// consensus-microdesc for the consensus and GET /tor/micro/d/<unpadded-base64
// sha256> for each
// microdescriptor. The response is plain HTTP (no TLS — the TLS terminates at
// the relay, and the circuit's onion encryption protects the body in transit).
func fetchViaFallbackCircuit(ctx context.Context, opts FetchOptions) (map[string]*Router, *ConsensusMeta, error) {
	fallbacks := fallback.DefaultFallbacks
	for _, fb := range fallbacks {
		if ctx.Err() != nil {
			break
		}
		routers, meta, err := fetchFromOneFallback(ctx, opts, fb)
		if err == nil {
			return routers, meta, nil
		}
		// Continue to the next fallback on any failure (dial, handshake,
		// circuit, or HTTP). This is the resilience fallbacks provide.
	}
	return nil, nil, errors.New("directory: no fallback directory cache succeeded")
}

// fetchFromOneFallback performs the full bootstrap from a single fallback.
func fetchFromOneFallback(ctx context.Context, opts FetchOptions, fb fallback.Fallback) (map[string]*Router, *ConsensusMeta, error) {
	addr := fb.PreferredAddr()
	// Dial the fallback's ORPort over TLS, verifying its RSA identity digest.
	// The TLS link authenticates the relay; CREATE_FAST then derives circuit
	// keys without needing the relay's onion key (which the fallback list
	// does not carry).
	l, err := link.DialWithUpstream(ctx, opts.UpstreamProxy, addr, fb.RSAFingerprint[:], [32]byte{})
	if err != nil {
		return nil, nil, fmt.Errorf("dial fallback %s: %w", fb.HexFingerprint(), err)
	}
	defer l.Close()

	// Build a one-hop CREATE_FAST circuit to the fallback.
	circ, err := circuit.NewOneHopFast(ctx, l)
	if err != nil {
		return nil, nil, fmt.Errorf("fast circuit to %s: %w", fb.HexFingerprint(), err)
	}
	defer circ.Close()

	// Open a BEGIN_DIR stream (a directory stream to the relay's dirport).
	stream, err := circ.BeginDir(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("BEGIN_DIR to %s: %w", fb.HexFingerprint(), err)
	}
	defer stream.Close()

	// Fetch the microconsensus over the directory stream.
	consensus, err := httpGetOverStream(ctx, stream, "/tor/status-vote/current/consensus-microdesc", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("consensus from %s: %w", fb.HexFingerprint(), err)
	}
	if !looksLikeConsensus(consensus) {
		return nil, nil, fmt.Errorf("consensus from %s: not a consensus", fb.HexFingerprint())
	}
	routers, err := ParseConsensus(consensus)
	if err != nil {
		return nil, nil, fmt.Errorf("parse consensus from %s: %w", fb.HexFingerprint(), err)
	}
	meta, _ := ParseConsensusMeta(consensus)

	// Fetch microdescriptors over the same stream. The directory protocol
	// allows pipelining requests on a single BEGIN_DIR stream, but to keep
	// the read loop simple we fetch them sequentially.
	type job struct {
		b64 string
		r   *Router
	}
	var jobs []job
	for _, r := range routers {
		// Same encoding as fetch.go: the dirport takes the raw unpadded
		// base64 SHA-256 token from the consensus "m" line (dircache.c:
		// DSR_DIGEST256 | DSR_BASE64; a hex digest is silently dropped
		// from the spool and the request 404s).
		jobs = append(jobs, job{base64.RawStdEncoding.EncodeToString(r.MicrodescDigest[:]), r})
		if opts.MaxMicrodescs > 0 && len(jobs) >= opts.MaxMicrodescs {
			break
		}
	}
	var mdBuf strings.Builder
	fetched := 0
	for _, j := range jobs {
		body, err := httpGetOverStream(ctx, stream, "/tor/micro/d/"+j.b64, addr)
		if err != nil {
			continue
		}
		mdBuf.Write(body)
		if !strings.HasSuffix(string(body), "\n") {
			mdBuf.WriteByte('\n')
		}
		mdBuf.WriteByte('\n')
		fetched++
	}
	if fetched == 0 {
		// Return the consensus-only routers; microdescriptors are best-effort
		// during bootstrap (the C client also proceeds with a partial set).
		return routers, meta, nil
	}
	if err := ParseMicrodescriptors([]byte(mdBuf.String()), routers); err != nil {
		return routers, meta, fmt.Errorf("parse microdescriptors from %s: %w", fb.HexFingerprint(), err)
	}
	return routers, meta, nil
}

// httpGetOverStream sends an HTTP/1.1 GET for path over a BEGIN_DIR stream
// and returns the response body. host is used as the HTTP Host header (the
// relay's ORPort address). The directory protocol is plain HTTP over the
// circuit; the relay responds with a complete HTTP/1.1 message and then
// closes the stream (RELAY_END), so we read until END.
func httpGetOverStream(ctx context.Context, stream interface {
	Write([]byte) (int, error)
	Read() ([]byte, error)
}, path, host string) ([]byte, error) {
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := stream.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	// Read the full HTTP response: accumulate DATA cells until END (errEOF).
	var raw strings.Builder
	for {
		// Honor the context deadline between reads.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		chunk, err := stream.Read()
		if err != nil {
			if errors.Is(err, circuit.ErrEOF) {
				break
			}
			return nil, fmt.Errorf("read response: %w", err)
		}
		raw.Write(chunk)
	}
	body, err := parseHTTPBody(raw.String())
	if err != nil {
		return nil, err
	}
	return body, nil
}

// parseHTTPBody extracts the body from a raw HTTP/1.1 response, checking the
// status line is 200 OK. It mirrors what net/http would do, but operates on
// the raw bytes we accumulated from the circuit stream.
func parseHTTPBody(raw string) ([]byte, error) {
	// Find the end of the status line.
	br := bufio.NewReader(strings.NewReader(raw))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("parse http response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
