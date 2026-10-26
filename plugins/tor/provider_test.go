package tor

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	pub "github.com/goose-network/goose-plugin-api"

	"github.com/goose-network/tor-go/internal/torclient"
)

// fakeClient is a stand-in for the tor-go client used by provider tests that
// exercise the dial path without a real Tor bootstrap. It satisfies the
// surface the provider's dialStream uses; the exits field simulates the
// per-exit roster surface (exitLister + exitPinner) when set.
type fakeClient struct {
	onDial func(target string) (io.ReadWriteCloser, error)
	exits  []torclient.RouterInfo // when non-nil, the fake implements the roster + pin dials
	lastTo string                // digest of the last pinned dial ("" when unpinned)
}

func (f *fakeClient) DialStream(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	if f.onDial == nil {
		return nil, errors.New("fakeClient: no dial behavior configured")
	}
	return f.onDial(target)
}

func (f *fakeClient) ExitInfos() []torclient.RouterInfo { return f.exits }

func (f *fakeClient) DialStreamViaExit(ctx context.Context, hexDigest, target string) (io.ReadWriteCloser, error) {
	f.lastTo = hexDigest
	if f.onDial == nil {
		return nil, errors.New("fakeClient: no dial behavior configured")
	}
	return f.onDial(target)
}

// echoRW is a minimal in-memory ReadWriteCloser that discards writes and
// reads EOF, so a dialed conn can be closed immediately.
type echoRW struct{}

func (echoRW) Write(p []byte) (int, error) { return len(p), nil }
func (echoRW) Read(p []byte) (int, error)  { return 0, io.EOF }
func (echoRW) Close() error                { return nil }

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

// TestParseConfigStripsInjectedDialers verifies the engine-injected reserved
// keys are dropped before the JSON round-trip (a func/interface value under
// them would break json.Marshal) and that the caller's map is not mutated.
func TestParseConfigStripsInjectedDialers(t *testing.T) {
	in := map[string]any{
		pub.StackDialerKey:    func() {}, // funcs break json.Marshal
		pub.UpstreamDialerKey: func() {},
		"path_len":            3,
	}
	pc, err := parseConfig(in)
	if err != nil {
		t.Fatalf("parseConfig with injected dialers: %v", err)
	}
	if pc.PathLen != 3 {
		t.Fatalf("path_len = %d, want 3", pc.PathLen)
	}
	if _, still := in[pub.StackDialerKey]; !still {
		t.Fatal("parseConfig must not mutate the caller's config map")
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

// TestProviderRegistered verifies the init() registrations landed in the
// goose plugin registries: the provider under "tor" and the outbound
// protocol under "tor".
func TestProviderRegistered(t *testing.T) {
	f, ok := pub.LookupProvider("tor")
	if !ok {
		t.Fatal(`provider "tor" not registered`)
	}
	if f == nil {
		t.Fatal("registered provider factory is nil")
	}
	of, ok := pub.Lookup("tor")
	if !ok {
		t.Fatal(`outbound protocol "tor" not registered`)
	}
	if of == nil {
		t.Fatal("registered outbound factory is nil")
	}
}

// TestOutboundsEmptyUntilReady verifies the bootstrap pattern: a provider
// whose tor-go client has not connected reports an empty outbound set (not
// an error), so the engine's pool simply stays empty.
func TestOutboundsEmptyUntilReady(t *testing.T) {
	// Build a provider pointing at a directory source that cannot be
	// fetched (bogus upstream), so the background bootstrap fails and the
	// client never comes up. The provider must still be instantiable and
	// report an empty set — the goal is resilience, not a factory error.
	p, err := NewProvider(map[string]any{
		"upstream_proxy":        "127.0.0.1:1", // nothing listens here
		"fetch_timeout_seconds": 1,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
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

// TestOutboundsAfterReady verifies the ready flip: once the client is
// connected, Outbounds emits one "tor" protocol outbound wired to this
// provider, and it signals Watch. No address is emitted — the dial goes
// in memory through the live provider.
func TestOutboundsAfterReady(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "tor-test"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}

	p.mu.Lock()
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
	if out[0].ID != "tor-test" || out[0].Protocol != "tor" {
		t.Fatalf("unexpected outbound: %+v", out[0])
	}
	tunnel, _ := out[0].Config["tunnel"].(string)
	if tunnel != "tor-test" {
		t.Fatalf("outbound tunnel = %q, want %q", tunnel, "tor-test")
	}
	if _, hasAddress := out[0].Config["address"]; hasAddress {
		t.Fatal("in-memory outbound must not carry an address: there is no listener")
	}

	// Watch must have been signaled by signalWatch.
	select {
	case <-p.Watch():
	default:
		t.Fatal("watch channel was not signaled")
	}
}

// TestOutboundFactory verifies the "tor" protocol factory parses the
// provider-emitted config shapes and that dials fail fast without a live
// provider (the engine reports the error and falls back to other
// outbounds).
func TestOutboundFactory(t *testing.T) {
	o, err := New(map[string]any{"id": "tor", "tunnel": "tor"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if o.Protocol() != "tor" || o.ID() != "tor" || o.Address() != "" {
		t.Fatalf("outbound: %q %q %q", o.ID(), o.Protocol(), o.Address())
	}
	if o.Location() != nil {
		t.Fatal("Location should be nil")
	}

	// Defaults for a minimal hand-written config.
	bare, err := New(map[string]any{})
	if err != nil {
		t.Fatalf("New(bare): %v", err)
	}
	if bare.ID() != "tor" || bare.Protocol() != "tor" {
		t.Fatalf("bare outbound: %q %q", bare.ID(), bare.Protocol())
	}

	// UDP is refused without touching the registry.
	if _, err := bare.DialContext(context.Background(), pub.NetworkUDP, "example.com:53"); err == nil {
		t.Fatal("UDP dial should fail: Tor tunnels TCP only")
	}

	// No live provider registered under the tunnel id: fail fast with a
	// diagnosable error instead of hanging.
	_, err = bare.DialContext(context.Background(), pub.NetworkTCP, "example.com:80")
	if err == nil {
		t.Fatal("dial without a live provider should fail")
	}
}

// TestOutboundTargetPolicy verifies the dial path applies the same target
// policy the SOCKS5 server does: .onion refused, port 0 refused, private
// targets refused unless allow_private is set.
func TestOutboundTargetPolicy(t *testing.T) {
	o, err := New(map[string]any{"id": "tor", "tunnel": "tor"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		target  string
		network pub.Network
		wantErr bool
		reason  string
	}{
		{"examplebook.onion:443", pub.NetworkTCP, true, "onion target"},
		{"example.com:0", pub.NetworkTCP, true, "port 0"},
		{"192.168.1.10:80", pub.NetworkTCP, true, "private target"},
		{"127.0.0.1:8080", pub.NetworkTCP, true, "loopback target"},
		{"bad-target", pub.NetworkTCP, true, "unparseable target"},
	}
	for _, c := range cases {
		_, err := o.DialContext(context.Background(), c.network, c.target)
		if (err != nil) != c.wantErr {
			t.Fatalf("%s: dial err=%v, wantErr=%v", c.reason, err, c.wantErr)
		}
	}

	// A hostname target with no live provider still fails — the provider
	// lookup error, not the policy check.
	if _, err := o.DialContext(context.Background(), pub.NetworkTCP, "example.com:80"); err == nil {
		t.Fatal("dial without a live provider should fail")
	}

	// allow_private=true: the policy check passes and the dial reaches the
	// provider lookup.
	privateOK, err := New(map[string]any{"id": "tor", "tunnel": "tor", "allow_private": true})
	if err != nil {
		t.Fatalf("New(allow_private): %v", err)
	}
	if _, err := privateOK.DialContext(context.Background(), pub.NetworkTCP, "192.168.1.10:80"); err == nil {
		t.Fatal("dial without a live provider should still fail (past the policy check)")
	}
}

// TestOutboundDialsThroughLiveProvider verifies the full in-memory path: the
// provider is registered under the outbound's tunnel id, its dialStream
// returns a wrapped stream, and the conn satisfies net.Conn.
func TestOutboundDialsThroughLiveProvider(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "tor-live"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
		client:  &fakeClient{onDial: func(target string) (io.ReadWriteCloser, error) { return echoRW{}, nil }},
	}
	registerLiveProvider(p)
	defer unregisterLiveProvider(p)

	o, err := New(map[string]any{"id": "tor-live", "tunnel": "tor-live"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := o.DialContext(context.Background(), pub.NetworkTCP, "example.com:80")
	if err != nil {
		t.Fatalf("DialContext through live provider: %v", err)
	}
	defer conn.Close()
	if conn.LocalAddr().Network() != "tor" || conn.RemoteAddr().String() != "tor-circuit" {
		t.Fatalf("conn addrs: %v %v", conn.LocalAddr(), conn.RemoteAddr())
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline should be a no-op success: %v", err)
	}
}

// TestDialStreamFailsWithoutClient verifies dialStream errors fast when the
// client is not running instead of panicking or hanging.
func TestDialStreamFailsWithoutClient(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "tor-noclient"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	if _, err := p.dialStream(context.Background(), "example.com:80"); err == nil {
		t.Fatal("dialStream without a client should fail")
	}
}

// TestCloseStopsBootstrap verifies Close cancels the background bootstrap
// goroutine and returns, even when the bootstrap is stuck retrying.
func TestCloseStopsBootstrap(t *testing.T) {
	pAny, err := NewProvider(map[string]any{
		"upstream_proxy":        "127.0.0.1:1",
		"fetch_timeout_seconds": 1,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
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
	// Close deregistered the live provider: dials now fail the lookup.
	if _, ok := lookupLiveProvider("tor"); ok {
		t.Fatal("default tunnel id should be gone after Close")
	}
}

// TestOutboundsEmitPerExitRelays covers the per-server list form: once the
// client is ready and reports an exit roster, Outbounds emits the general
// outbound plus one per Exit-flagged relay, each carrying the digest that
// pins the circuit's exit hop.
func TestOutboundsEmitPerExitRelays(t *testing.T) {
	roster := []torclient.RouterInfo{
		{Nickname: "relayA", IDDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Address: "1.2.3.4:9001", IsExit: true},
		{Nickname: "relayB", IDDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Address: "5.6.7.8:9002", IsExit: true},
	}
	p := &Provider{
		cfg:     providerConfig{OutboundID: "tor-list"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
		client:  &fakeClient{exits: roster},
	}
	p.mu.Lock()
	p.ready = true
	p.mu.Unlock()

	out, err := p.Outbounds(context.Background())
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d outbounds, want 3 (general + 2 exits): %+v", len(out), out)
	}
	if out[0].ID != "tor-list" {
		t.Fatalf("out[0].ID = %q, want the general outbound first", out[0].ID)
	}
	if _, hasExit := out[0].Config["exit"]; hasExit {
		t.Fatal("general outbound must not carry an exit pin")
	}

	// Per-exit entries: id is provider id + nickname + digest prefix, config
	// carries the full digest + display fields.
	for i, want := range []struct{ id, digest, name, addr string }{
		{"tor-list-relayA-aaaaaaaaaaaa", roster[0].IDDigest, "relayA", "1.2.3.4:9001"},
		{"tor-list-relayB-bbbbbbbbbbbb", roster[1].IDDigest, "relayB", "5.6.7.8:9002"},
	} {
		got := out[1+i]
		if got.ID != want.id || got.Protocol != "tor" {
			t.Fatalf("per-exit outbound %d = %q (%s), want %q", i, got.ID, got.Protocol, want.id)
		}
		if digest, _ := got.Config["exit"].(string); digest != want.digest {
			t.Fatalf("outbound %s exit digest = %q, want %q", got.ID, digest, want.digest)
		}
		if name, _ := got.Config["exit_name"].(string); name != want.name {
			t.Fatalf("outbound %s exit_name = %q, want %q", got.ID, name, want.name)
		}
		if addr, _ := got.Config["address"].(string); addr != want.addr {
			t.Fatalf("outbound %s address = %q, want %q", got.ID, addr, want.addr)
		}
		if tunnel, _ := got.Config["tunnel"].(string); tunnel != "tor-list" {
			t.Fatalf("outbound %s tunnel = %q, want tor-list (the general provider)", got.ID, tunnel)
		}
	}
}

// TestPerExitOutboundDialPinsExit verifies the per-exit dial path end to end
// through the outbound factory: a dial on a per-relay outbound resolves the
// live provider and reaches the client with that relay's digest, while the
// general outbound dials unpinned. The per-exit outbound's Address() reports
// the relay's OR address.
func TestPerExitOutboundDialPinsExit(t *testing.T) {
	digest := "cccccccccccccccccccccccccccccccccccccccc"
	fc := &fakeClient{
		onDial: func(target string) (io.ReadWriteCloser, error) { return echoRW{}, nil },
		exits:  []torclient.RouterInfo{{Nickname: "relayC", IDDigest: digest, Address: "9.9.9.9:9003", IsExit: true}},
	}
	p := &Provider{
		cfg:     providerConfig{OutboundID: "tor-pin"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
		client:  fc,
	}
	p.mu.Lock()
	p.ready = true
	p.mu.Unlock()
	registerLiveProvider(p)
	defer unregisterLiveProvider(p)

	pinned, err := New(map[string]any{
		"id":        "tor-pin-relayC-cccccccccccc",
		"tunnel":    "tor-pin",
		"exit":      digest,
		"exit_name": "relayC",
	})
	if err != nil {
		t.Fatalf("New(per-exit): %v", err)
	}
	if addr := pinned.Address(); addr != "9.9.9.9:9003" {
		t.Fatalf("per-exit Address() = %q, want the relay's OR address", addr)
	}
	if _, err := pinned.DialContext(context.Background(), pub.NetworkTCP, "example.com:80"); err != nil {
		t.Fatalf("pinned dial: %v", err)
	}
	if fc.lastTo != digest {
		t.Fatalf("client saw pin %q, want %q", fc.lastTo, digest)
	}

	general, err := New(map[string]any{"id": "tor-pin", "tunnel": "tor-pin"})
	if err != nil {
		t.Fatalf("New(general): %v", err)
	}
	fc.lastTo = "sentinel"
	if _, err := general.DialContext(context.Background(), pub.NetworkTCP, "example.com:80"); err != nil {
		t.Fatalf("general dial: %v", err)
	}
	if fc.lastTo != "sentinel" {
		t.Fatalf("general dial reached DialStreamViaExit (pin %q), want the unpinned path", fc.lastTo)
	}
}

// TestPerExitDialWithoutPinnerSupport verifies a client that lacks the
// pin surface (an embedder predating it) fails the pinned dial fast with a
// diagnosable error while general dials still work.
func TestPerExitDialWithoutPinnerSupport(t *testing.T) {
	bare := struct{ streamDialer }{streamDialer: &fakeClient{
		onDial: func(target string) (io.ReadWriteCloser, error) { return echoRW{}, nil },
	}}
	p := &Provider{
		cfg:     providerConfig{OutboundID: "tor-bare"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
		client:  bare,
	}
	registerLiveProvider(p)
	defer unregisterLiveProvider(p)

	pinned, err := New(map[string]any{"id": "tor-bare-x", "tunnel": "tor-bare", "exit": strings.Repeat("d", 40)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := pinned.DialContext(context.Background(), pub.NetworkTCP, "example.com:80"); err == nil {
		t.Fatal("pinned dial on a client without pin support should fail")
	}
	general, err := New(map[string]any{"id": "tor-bare", "tunnel": "tor-bare"})
	if err != nil {
		t.Fatalf("New(general): %v", err)
	}
	if _, err := general.DialContext(context.Background(), pub.NetworkTCP, "example.com:80"); err != nil {
		t.Fatalf("general dial must still work: %v", err)
	}
}
