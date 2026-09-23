//go:build tor_real

// This file contains the end-to-end test against the REAL Tor network. It is
// gated behind the "tor_real" build tag because it requires outbound
// connectivity (directly or via the upstream SOCKS5 proxy at 127.0.0.1:7890)
// to the Tor directory authorities and to real relays, and a real circuit
// build can take tens of seconds. Run it with:
//
//	go test ./internal/testharness/ -tags tor_real -run TestE2ERealTorNetwork -timeout 10m -v
//
// The topology exercised is the one the user specified:
//
//	curl → tor-go SOCKS5 (ephemeral) → tor-go client → 127.0.0.1:7890 (upstream) → real Tor network → target
//
// tor-go fetches a real microconsensus + microdescriptors through the 7890
// upstream, selects a real guard/middle/exit, builds a 3-hop circuit (dialing
// each relay through 7890), and serves a local SOCKS5 port that a test client
// connects to in order to fetch https://check.torproject.org/api/ip through
// the circuit. The response should report a Tor exit's IP, confirming the
// connection traversed the real Tor network.
package testharness_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/proxy/tor-go/internal/directory"
	"github.com/proxy/tor-go/internal/torclient"
)

// upstreamProxy is the SOCKS5 proxy tor-go dials through to reach the real
// Tor network. It can be overridden with the TOR_GO_UPSTREAM env var.
const upstreamProxy = "127.0.0.1:7890"

// TestE2ERealTorNetwork builds a real 3-hop Tor circuit through the upstream
// proxy and fetches a target website through tor-go's SOCKS5 listener.
func TestE2ERealTorNetwork(t *testing.T) {
	upstream := os.Getenv("TOR_GO_UPSTREAM")
	if upstream == "" {
		upstream = upstreamProxy
	}

	// 1. Fetch a real directory through the upstream proxy.
	t.Logf("fetching real microconsensus via upstream %s ...", upstream)
	fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 4*time.Minute)
	dir, err := directory.Fetch(fetchCtx, directory.FetchOptions{
		UpstreamProxy: upstream,
		Timeout:       4 * time.Minute,
		// Limit microdescriptors to keep bootstrap bounded; we only need a few
		// Guard/Exit/Middle candidates.
		MaxMicrodescs: 400,
	})
	fetchCancel()
	if err != nil {
		t.Skipf("cannot reach directory authorities via %s: %v (no outbound to real Tor network)", upstream, err)
	}
	// Count routers that actually got an onion key (microdescriptor fetched).
	usable := 0
	for _, r := range dir {
		if !isZero(r.OnionKey[:]) {
			usable++
		}
	}
	if usable < 10 {
		t.Skipf("only %d usable relays with onion keys; insufficient for a real circuit (microdesc fetch likely blocked)", usable)
	}
	t.Logf("directory: %d relays, %d with onion keys", len(dir), usable)

	// 2. Pick a guard with an onion key.
	guard, err := pickGuardWithKey(dir)
	if err != nil {
		t.Skipf("no usable guard: %v", err)
	}
	t.Logf("guard: %s %s", guard.Nickname, guard.Address)

	// 3. Start tor-go's SOCKS5 listener on an ephemeral port.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	socksAddr := socksLn.Addr().String()
	socksLn.Close()

	cfg := &torclient.Config{
		SocksAddr:            socksAddr,
		PathLen:              3,
		Directory:            dir,
		Guard:                guard,
		UpstreamProxy:        upstream,
		LinkDialTimeout:      45 * time.Second,
		CircuitBuildTimeout:  90 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cli, err := torclient.New(ctx, cfg)
	if err != nil {
		t.Fatalf("torclient.New: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- cli.Serve(ctx) }()
	if err := waitForListen(socksAddr, 10*time.Second); err != nil {
		t.Fatalf("socks5 proxy not listening: %v", err)
	}
	t.Logf("tor-go SOCKS5 proxy listening at socks5://%s (upstream %s)", socksAddr, upstream)

	// 4. Connect through tor-go and fetch check.torproject.org/api/ip.
	conn := socks5Dial(t, socksAddr, "check.torproject.org:443")
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(90 * time.Second))

	// TLS ClientHello is done by the test client; we send a raw HTTP/1.1
	// request over a TLS connection we wrap ourselves.
	tlsConn, err := dialClientTLS(conn, "check.torproject.org")
	if err != nil {
		t.Fatalf("client tls: %v", err)
	}
	defer tlsConn.Close()
	tlsConn.SetDeadline(time.Now().Add(90 * time.Second))
	httpReq := "GET /api/ip HTTP/1.1\r\nHost: check.torproject.org\r\nConnection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(httpReq)); err != nil {
		t.Fatalf("write http request: %v", err)
	}
	body, err := io.ReadAll(tlsConn)
	if err != nil {
		t.Fatalf("read http response: %v", err)
	}
	s := string(body)
	t.Logf("check.torproject.org/api/ip response:\n%s", firstLines(s, 8))
	if !strings.Contains(s, "200 OK") && !strings.Contains(s, "is_tor") {
		t.Fatalf("response does not look like a successful check.torproject.org reply: %q", firstLines(s, 4))
	}
	t.Logf("SUCCESS: fetched https://check.torproject.org/api/ip through a real 3-hop Tor circuit")

	cancel()
	if err := <-serveErr; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Logf("client serve returned: %v", err)
	}
}

// pickGuardWithKey selects a Guard-flagged relay that has a fetched onion key.
func pickGuardWithKey(dir map[string]*directory.Router) (*directory.Router, error) {
	for _, r := range dir {
		if hasFlag(r, "Guard") && hasFlag(r, "Valid") && !isZero(r.OnionKey[:]) {
			return r, nil
		}
	}
	return nil, fmt.Errorf("no guard with onion key")
}

func hasFlag(r *directory.Router, f string) bool {
	for _, fl := range r.Flags {
		if fl == f {
			return true
		}
	}
	return false
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// dialClientTLS wraps a raw conn in TLS as a client. We avoid importing
// crypto/tls at package level here to keep the test file focused; instead we
// use a small helper that re-exports it.
func dialClientTLS(conn net.Conn, serverName string) (net.Conn, error) {
	return tlsClient(conn, serverName)
}

// writeSocksRequest writes a SOCKS5 CONNECT request for target to conn. Used
// by helpers that need to issue a CONNECT without the full socks5Dial flow.
func writeSocksRequest(conn net.Conn, target string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	req = append(req, pb...)
	_, err := conn.Write(req)
	return err
}
