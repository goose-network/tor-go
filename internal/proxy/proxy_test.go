package proxy_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/proxy/tor-go/internal/proxy"
	"github.com/proxy/tor-go/internal/socks5"
)

// echoListener starts a TCP echo server on an ephemeral port and returns its
// address. It echoes bytes back to the writer.
func echoListener(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// TestDialDirect verifies proxy.Dial with an empty upstream dials the target
// directly and data round-trips.
func TestDialDirect(t *testing.T) {
	target := echoListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.Dial(ctx, "", target)
	if err != nil {
		t.Fatalf("Dial direct: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	msg := []byte("hello-direct")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

// TestDialThroughSOCKS5 verifies proxy.Dial routes through a SOCKS5 upstream.
// We run the tor-go socks5 server as the upstream, with a dialer that dials
// the echo target directly.
func TestDialThroughSOCKS5(t *testing.T) {
	target := echoListener(t)

	// Upstream SOCKS5 server: a tor-go socks5.Server whose dialer dials the
	// target directly.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	upstreamAddr := upstreamLn.Addr().String()
	upstreamLn.Close()

	dialer := &directDialer{}
	srv := socks5.New(upstreamAddr, dialer)
	go srv.ListenAndServe()
	if err := waitForListen(upstreamAddr, 3*time.Second); err != nil {
		t.Fatalf("upstream not listening: %v", err)
	}
	defer srv.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.Dial(ctx, upstreamAddr, target)
	if err != nil {
		t.Fatalf("Dial through socks5: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	msg := []byte("hello-via-socks5")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

// TestDialSOCKS5Refused verifies proxy.Dial returns an error (not a nil conn)
// when the SOCKS5 upstream reports a failure for an unreachable target.
func TestDialSOCKS5Refused(t *testing.T) {
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	upstreamAddr := upstreamLn.Addr().String()
	upstreamLn.Close()

	srv := socks5.New(upstreamAddr, &directDialer{})
	go srv.ListenAndServe()
	if err := waitForListen(upstreamAddr, 3*time.Second); err != nil {
		t.Fatalf("upstream not listening: %v", err)
	}
	defer srv.Shutdown()

	// A closed port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := proxy.Dial(ctx, upstreamAddr, closedAddr)
	if err == nil {
		conn.Close()
		t.Fatalf("Dial to closed port succeeded; want error")
	}
}

// directDialer implements socks5.Dialer by dialing the target directly.
type directDialer struct{}

func (d *directDialer) DialStream(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	var dl net.Dialer
	c, err := dl.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func waitForListen(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errTimeout
}

var errTimeout = errTimeoutErr{}

type errTimeoutErr struct{}

func (errTimeoutErr) Error() string { return "timeout waiting for listener" }
