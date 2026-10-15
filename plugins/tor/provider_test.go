package tor

import (
	"context"
	"net"
	"testing"
	"time"

	pub "github.com/goose-network/goose-plugin-api"
)

// fakeTorSocks starts a loopback listener standing in for the tor-go SOCKS5
// server, so provider tests can exercise the ready-flip path without a real
// Tor bootstrap. It does not need to speak SOCKS5; the provider only checks
// that the port accepts a TCP connection.
func fakeTorSocks(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake socks listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Answer nothing; connections are liveness probes.
			_ = conn
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		<-done
	}
}

func TestParseConfig(t *testing.T) {
	pc, err := parseConfig(map[string]any{
		"upstream_proxy":            "127.0.0.1:7890",
		"path_len":                  3,
		"max_microdescs":            400,
		"verify_signatures":         true,
		"link_dial_timeout_seconds": 45,
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if pc.UpstreamProxy != "127.0.0.1:7890" || pc.PathLen != 3 || pc.MaxMicrodescs != 400 {
		t.Fatalf("unexpected config: %+v", pc)
	}
	if pc.VerifySignatures == nil || !*pc.VerifySignatures {
		t.Fatal("verify_signatures not parsed")
	}
	if pc.LinkDialTimeoutSeconds != 45 {
		t.Fatalf("link dial timeout = %d, want 45", pc.LinkDialTimeoutSeconds)
	}
}

func TestParseConfigVerifySignaturesDefaultsOn(t *testing.T) {
	// Absent config must default verify_signatures ON: the dirports serve
	// plain HTTP and the signature quorum is the consensus's only
	// authentication. New (not parseConfig) applies the default, since
	// parseConfig only round-trips what the caller provided.
	pAny, err := New(map[string]any{
		"socks_listen": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := pAny.(*Provider)
	defer p.Close()
	if p.cfg.VerifySignatures == nil || !*p.cfg.VerifySignatures {
		t.Fatal("verify_signatures should default to true")
	}
	p2Any, err := New(map[string]any{
		"socks_listen":      "127.0.0.1:0",
		"verify_signatures": false,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p2 := p2Any.(*Provider)
	defer p2.Close()
	if p2.cfg.VerifySignatures == nil || *p2.cfg.VerifySignatures {
		t.Fatal("explicit verify_signatures=false should be honored")
	}
}

func TestParseConfigNil(t *testing.T) {
	pc, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig(nil): %v", err)
	}
	if pc != (providerConfig{}) {
		t.Fatalf("expected zero config, got %+v", pc)
	}
}

// TestProviderRegistered verifies the init() registration landed in the
// goose plugin registry under the name "tor".
func TestProviderRegistered(t *testing.T) {
	f, ok := pub.LookupProvider("tor")
	if !ok {
		t.Fatal(`provider "tor" not registered`)
	}
	if f == nil {
		t.Fatal("registered factory is nil")
	}
}

// TestOutboundsEmptyUntilReady verifies the bootstrap pattern: a provider
// whose tor-go client has not started listening reports an empty outbound
// set (not an error), so the engine's pool simply stays empty.
func TestOutboundsEmptyUntilReady(t *testing.T) {
	// Build a provider pointing at a directory source that cannot be
	// fetched (bogus upstream), so the background bootstrap fails and the
	// client never comes up. The provider must still be instantiable and
	// report an empty set — the goal is resilience, not a factory error.
	p, err := New(map[string]any{
		"upstream_proxy":        "127.0.0.1:1", // nothing listens here
		"fetch_timeout_seconds": 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.(*Provider).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := p.Outbounds(ctx)
	if err != nil {
		t.Fatalf("Outbounds while retrying should return an empty set, got err=%v", err)
	}
	if len(out) != 0 {
		t.Fatalf("got %d outbounds before ready, want 0", len(out))
	}
}

// TestOutboundsAfterReady verifies the ready flip: once a listener answers
// on the client's SOCKS address, Outbounds emits one socks5 outbound with
// the configured id and that address, and it signals Watch.
func TestOutboundsAfterReady(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "tor-test"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	socks, stopSocks := fakeTorSocks(t)
	defer stopSocks()

	p.mu.Lock()
	p.listenOn = socks
	p.ready = true
	p.mu.Unlock()
	p.signalWatch()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := p.Outbounds(ctx)
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d outbounds, want 1", len(out))
	}
	if out[0].ID != "tor-test" || out[0].Protocol != "socks5" {
		t.Fatalf("unexpected outbound: %+v", out[0])
	}
	addr, _ := out[0].Config["address"].(string)
	if addr != socks {
		t.Fatalf("outbound address = %q, want %q", addr, socks)
	}

	// Watch must have been signaled by signalWatch.
	select {
	case <-p.Watch():
	default:
		t.Fatal("watch channel was not signaled")
	}
}

// TestCloseStopsBootstrap verifies Close cancels the background bootstrap
// goroutine and returns, even when the bootstrap is stuck retrying.
func TestCloseStopsBootstrap(t *testing.T) {
	pAny, err := New(map[string]any{
		"upstream_proxy":        "127.0.0.1:1",
		"fetch_timeout_seconds": 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := pAny.(*Provider)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The stopped channel is closed when the bootstrap goroutine exits; a
	// second receive on it must not block (idempotence).
	select {
	case <-p.stopped:
	default:
		t.Fatal("bootstrap goroutine still running after Close")
	}
}
