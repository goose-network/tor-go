package testharness_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/proxy/tor-go/internal/directory"
	"github.com/proxy/tor-go/internal/testharness"
	"github.com/proxy/tor-go/internal/torclient"
)

// socks5Dial performs a SOCKS5 CONNECT to target through the proxy at
// proxyAddr (no-auth). It returns the established connection.
func socks5Dial(t *testing.T, proxyAddr, target string) net.Conn {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		t.Fatalf("socks greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		t.Fatalf("socks greeting reply: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		t.Fatalf("socks greeting reply = %x, want 0500", resp)
	}
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	req = append(req, pb...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		t.Fatalf("socks request: %v", err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		t.Fatalf("socks reply header: %v", err)
	}
	if hdr[1] != 0x00 {
		conn.Close()
		t.Fatalf("socks reply REP = %d, want 0 (success)", hdr[1])
	}
	switch hdr[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 4))
	case 0x04:
		io.ReadFull(conn, make([]byte, 16))
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		io.ReadFull(conn, make([]byte, int(l[0])))
	}
	io.ReadFull(conn, make([]byte, 2))
	return conn
}

// TestE2ESocks5Proxy is the in-process end-to-end test: it runs the Tor
// client's SOCKS5 proxy on an ephemeral loopback port, routes a connection
// through it over a three-hop mock circuit, and verifies a real HTTP request
// is answered by a loopback origin server. (The SOCKS5 listener is on an
// ephemeral port because 127.0.0.1:7890 is reserved on this machine for the
// upstream proxy that tor-go dials through to reach the real Tor network —
// see TestE2ERealTorNetwork in e2e_real_test.go.)
func TestE2ESocks5Proxy(t *testing.T) {
	h, err := testharness.NewHarness(3)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	dir := buildDir(h)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from origin via tor-go (path=%s)", r.URL.Path)
	})
	origin := &http.Server{Handler: mux}
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer origin.Close()
	go origin.Serve(originLn)
	originAddr := originLn.Addr().String()

	// tor-go's SOCKS5 listener on an ephemeral port.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	socksAddr := socksLn.Addr().String()
	socksLn.Close()

	cfg := &torclient.Config{
		SocksAddr:           socksAddr,
		PathLen:             3,
		Directory:           dir,
		Guard:               dir[fmt.Sprintf("%x", h.GuardEntry().IDDigest[:])],
		LinkDialTimeout:     10 * time.Second,
		CircuitBuildTimeout: 15 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cli, err := torclient.New(ctx, cfg)
	if err != nil {
		t.Fatalf("torclient.New: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- cli.Serve(ctx) }()
	if err := waitForListen(socksAddr, 5*time.Second); err != nil {
		t.Fatalf("socks5 proxy not listening: %v", err)
	}
	t.Logf("tor-go SOCKS5 proxy listening at socks5://%s", socksAddr)

	conn := socks5Dial(t, socksAddr, originAddr)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	httpReq := fmt.Sprintf("GET /e2e HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originAddr)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		t.Fatalf("write http request: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read http response: %v", err)
	}
	if !strings.Contains(string(body), "hello from origin via tor-go") {
		t.Fatalf("response body = %q, want it to contain the origin marker", string(body))
	}
	if !strings.Contains(string(body), "path=/e2e") {
		t.Fatalf("response body = %q, want path=/e2e", string(body))
	}
	t.Logf("e2e HTTP response received through socks5://%s:\n%s", socksAddr, firstLines(string(body), 3))

	cancel()
	if err := <-serveErr; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Logf("client serve returned: %v", err)
	}
}

// TestE2ESocks5ProxyRefused verifies the SOCKS5 proxy returns a non-success
// reply code when the exit cannot connect to the target (closed port).
func TestE2ESocks5ProxyRefused(t *testing.T) {
	h, err := testharness.NewHarness(3)
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	defer h.Close()
	dir := buildDir(h)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := ln.Addr().String()
	ln.Close()

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	socksAddr := socksLn.Addr().String()
	socksLn.Close()

	cfg := &torclient.Config{
		SocksAddr:           socksAddr,
		PathLen:             3,
		Directory:           dir,
		Guard:               dir[fmt.Sprintf("%x", h.GuardEntry().IDDigest[:])],
		LinkDialTimeout:     10 * time.Second,
		CircuitBuildTimeout: 15 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cli, err := torclient.New(ctx, cfg)
	if err != nil {
		t.Fatalf("torclient.New: %v", err)
	}
	go cli.Serve(ctx)
	if err := waitForListen(socksAddr, 5*time.Second); err != nil {
		t.Fatalf("socks5 proxy not listening: %v", err)
	}

	conn, err := net.DialTimeout("tcp", socksAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(conn, make([]byte, 2))
	host, portStr, _ := net.SplitHostPort(closedAddr)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	req = append(req, pb...)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	conn.Write(req)
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("socks reply: %v", err)
	}
	if hdr[1] == 0x00 {
		t.Fatalf("socks reply REP = 0 (success) for closed port; want non-zero")
	}
	t.Logf("socks5 proxy correctly refused closed port with REP=%d", hdr[1])
}

// waitForListen polls until addr accepts a TCP connection or the timeout
// elapses.
func waitForListen(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

// firstLines returns the first n lines of s (for compact logging).
func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// Ensure the directory import is used.
var _ = directory.SelectGuard
