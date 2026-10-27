package tor

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	pub "github.com/goose-network/goose-plugin-api"

	"github.com/goose-network/tor-go/internal/directory"
	"github.com/goose-network/tor-go/internal/link"
	"github.com/goose-network/tor-go/internal/torclient"
)

// dialRecorder is the shared recording core of the fake stack and route
// dialers below: one entry per dial, "network address".
type dialRecorder struct {
	mu    sync.Mutex
	dials []string
}

func (r *dialRecorder) record(network, address string) {
	r.mu.Lock()
	r.dials = append(r.dials, network+" "+address)
	r.mu.Unlock()
}

func (r *dialRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.dials...)
}

// fakeStackDialer is a pub.StackDialer answering Dial with a recorded pipe
// conn.
type fakeStackDialer struct{ rec *dialRecorder }

func (f fakeStackDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.rec.record(network, address)
	c1, c2 := net.Pipe()
	go func() { <-ctx.Done(); _ = c2.Close() }()
	return c1, nil
}

// fakeUpstreamDialer is a pub.UpstreamDialer answering DialUpstream with a
// recorded pipe conn.
type fakeUpstreamDialer struct{ rec *dialRecorder }

func (f fakeUpstreamDialer) DialUpstream(ctx context.Context, network, address string) (net.Conn, error) {
	f.rec.record(network, address)
	c1, c2 := net.Pipe()
	go func() { <-ctx.Done(); _ = c2.Close() }()
	return c1, nil
}

// TestEngineLinkDialerPrecedence verifies the dialer choice NewProvider
// hands tor-go's link layer: an injected engine route (a goose
// outbound/pool/chain) outranks the engine stack, which outranks tor-go's
// own dialer, and the chosen dialer is called with the dial arguments
// verbatim. It also reports the route choice, which suppresses the raw
// upstream_proxy address.
func TestEngineLinkDialerPrecedence(t *testing.T) {
	d, viaRoute := engineLinkDialer(map[string]any{})
	if d != nil || viaRoute {
		t.Fatal("engineLinkDialer(empty) must be (nil, false)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stackRec, routeRec := &dialRecorder{}, &dialRecorder{}
	d, viaRoute = engineLinkDialer(map[string]any{
		pub.StackDialerKey:    fakeStackDialer{stackRec},
		pub.UpstreamDialerKey: fakeUpstreamDialer{routeRec},
	})
	if !viaRoute {
		t.Fatal("injected route not reported")
	}
	conn, err := d(ctx, "tcp", "128.31.0.39:9131")
	if err != nil {
		t.Fatalf("dial through the route: %v", err)
	}
	_ = conn.Close()
	if got := routeRec.recorded(); len(got) != 1 || got[0] != "tcp 128.31.0.39:9131" {
		t.Fatalf("route dialed %v, want one tcp dial to the authority ORPort", got)
	}
	if got := stackRec.recorded(); len(got) != 0 {
		t.Fatalf("stack dialed %v, want none — the route outranks the stack", got)
	}

	stackRec = &dialRecorder{}
	d, viaRoute = engineLinkDialer(map[string]any{
		pub.StackDialerKey: fakeStackDialer{stackRec},
	})
	if viaRoute {
		t.Fatal("stack-only injection must not report a route")
	}
	if _, err := d(ctx, "tcp", "128.31.0.39:9131"); err != nil {
		t.Fatalf("dial through the stack: %v", err)
	}
	if got := stackRec.recorded(); len(got) != 1 || got[0] != "tcp 128.31.0.39:9131" {
		t.Fatalf("stack dialed %v, want one tcp dial to the authority ORPort", got)
	}
}

// TestNewProviderRouteSupersedesRawUpstream verifies the factory behavior:
// an injected engine route carries the client's connections and the config's
// raw upstream_proxy address is dropped (tor-go would chain a SOCKS5 hop
// inside the route — double-proxying). The background bootstrap's directory
// fetch dials through the route, observable on the fake's recorder.
func TestNewProviderRouteSupersedesRawUpstream(t *testing.T) {
	routeRec := &dialRecorder{}
	p, err := NewProvider(map[string]any{
		"upstream_proxy":        "127.0.0.1:7890", // would double-proxy inside the route
		"fetch_timeout_seconds": 1,
		pub.UpstreamDialerKey:   fakeUpstreamDialer{routeRec},
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	prov := p.(*Provider)
	defer prov.Close()

	if prov.cfg.UpstreamProxy != "" {
		t.Fatalf("raw upstream_proxy = %q, want dropped for the injected route", prov.cfg.UpstreamProxy)
	}
	if !prov.viaRoute {
		t.Fatal("provider does not record the injected route")
	}

	// The bootstrap fetch dials the authorities through the route (not the
	// raw address, not a kernel socket). Poll: the fetch has a 1s timeout
	// and retries with backoff, so wait a few seconds for the first dial.
	deadline := time.Now().Add(5 * time.Second)
	for len(routeRec.recorded()) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := routeRec.recorded(); len(got) == 0 {
		t.Fatal("directory fetch never dialed through the injected route")
	}

	st := prov.Status()
	if st.Details["engine_route"] != true {
		t.Fatalf("Status engine_route = %v, want true", st.Details["engine_route"])
	}
	if st.Details["upstream_proxy"] != false {
		t.Fatalf("Status upstream_proxy = %v, want false (dropped for the route)", st.Details["upstream_proxy"])
	}
}

// fakeClient is a stand-in for the tor-go client used by provider tests that
// exercise the dial path without a real Tor bootstrap. It satisfies the
// surface the provider's dialStream uses; the exits field simulates the
// per-exit roster surface (exitLister + exitPinner) when set.
type fakeClient struct {
	onDial      func(target string) (io.ReadWriteCloser, error)
	exits       []torclient.RouterInfo // when non-nil, the fake implements the roster + pin dials
	connected   bool
	guard       *directory.Router
	routerCount int
	lastTo      string // digest of the last pinned dial ("" when unpinned)
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

// fakeClient's statusSource surface for Status tests: zero values report
// "not connected" and no guard, matching a client that is still booting.
func (f *fakeClient) Connected() bool          { return f.connected }
func (f *fakeClient) Guard() *directory.Router { return f.guard }
func (f *fakeClient) RouterCount() int         { return f.routerCount }

// statusFixture builds a Provider in a given observability state the way the
// lifecycle code would have left it.
func statusFixture(mutate func(p *Provider)) *Provider {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "tor", VerifySignatures: &[]bool{true}[0]},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	if mutate != nil {
		mutate(p)
	}
	return p
}

// TestStatusReporting walks the state machine Status() exposes: a fresh
// provider reports the bootstrap phase; a failed attempt adds the failure
// and the retry tick; connected adds guard facts; terminal error and Close
// take precedence. All states must be cheap field reads with no panic,
// including on a zero-value config (VerifySignatures nil).
func TestStatusReporting(t *testing.T) {
	// Bootstrapping: attempt underway, progress word as the message.
	st := statusFixture(func(p *Provider) { p.phase = "fetching directory" }).Status()
	if st.State != "bootstrapping" || st.Message != "fetching directory" {
		t.Fatalf("bootstrapping: state=%q message=%q", st.State, st.Message)
	}
	if st.Details["verify_signatures"] != true {
		t.Fatalf("verify_signatures default: %v", st.Details["verify_signatures"])
	}

	// Retrying: last failure as the message, with the retry tick.
	retryAt := time.Now().Add(30 * time.Second)
	st = statusFixture(func(p *Provider) {
		p.lastBootErr = errors.New("fetch directory: no route")
		p.attempts = 2
		p.nextRetry = retryAt
	}).Status()
	if st.State != "retrying" || st.Message != "fetch directory: no route" {
		t.Fatalf("retrying: state=%q message=%q", st.State, st.Message)
	}
	if st.Details["attempts"] != 2 {
		t.Fatalf("attempts: %v", st.Details["attempts"])
	}
	if _, ok := st.Details["next_retry_at"]; !ok {
		t.Fatal("retrying state must report next_retry_at")
	}

	// Running: guard facts from the live client surface.
	connected := &fakeClient{
		connected:   true,
		routerCount: 9182,
		guard: &directory.Router{RouterIdentity: link.RouterIdentity{
			Nickname: "moria1",
			Address:  "128.31.0.39:9131",
		}},
	}
	st = statusFixture(func(p *Provider) {
		p.ready = true
		p.phase = "running"
		p.connectedAt = time.Now().Add(-time.Minute)
		p.relays = 4000
		p.exitCount = 2743
		p.client = connected
	}).Status()
	if st.State != "running" || st.Message != "" {
		t.Fatalf("running: state=%q message=%q", st.State, st.Message)
	}
	if st.Details["guard"] != "moria1 (128.31.0.39:9131)" {
		t.Fatalf("guard: %v", st.Details["guard"])
	}
	if st.Details["guard_link_alive"] != true {
		t.Fatalf("guard_link_alive: %v", st.Details["guard_link_alive"])
	}
	if st.Details["relays"] != 9182 {
		t.Fatalf("live RouterCount must override the bootstrap count: %v", st.Details["relays"])
	}
	if st.Details["exits_in_roster"] != 2743 {
		t.Fatalf("exits_in_roster: %v", st.Details["exits_in_roster"])
	}
	if _, ok := st.Details["connected_since"]; !ok {
		t.Fatal("running state must report connected_since")
	}

	// Running without the client status surface (mock predates it): no
	// guard facts, bootstrap relays count stands.
	bare := &fakeClient{}
	st = statusFixture(func(p *Provider) {
		p.ready = true
		p.relays = 9182
		p.client = bare
	}).Status()
	if st.State != "running" {
		t.Fatalf("bare running: state=%q", st.State)
	}
	if _, ok := st.Details["guard"]; ok {
		t.Fatal("no guard must be reported when the client has none")
	}

	// Terminal error wins over phase bookkeeping.
	st = statusFixture(func(p *Provider) {
		p.startErr = errors.New("init tor client: bad config")
		p.phase = "connecting guard"
	}).Status()
	if st.State != "error" || st.Message != "init tor client: bad config" {
		t.Fatalf("error: state=%q message=%q", st.State, st.Message)
	}

	// Stopped wins over everything.
	st = statusFixture(func(p *Provider) {
		p.closed = true
		p.ready = true
	}).Status()
	if st.State != "stopped" {
		t.Fatalf("stopped: state=%q", st.State)
	}

	// Zero-value config must not panic (VerifySignatures nil → default on).
	st = statusFixture(nil).Status()
	if st.State != "bootstrapping" {
		t.Fatalf("zero fixture: state=%q", st.State)
	}
}

// TestStatusRunsConcurrentlyWithOutbounds pins the engine contract: Status
// is polled outside the provider's locks while Outbounds runs; both take
// p.mu, so run them concurrently under -race.
func TestStatusRunsConcurrentlyWithOutbounds(t *testing.T) {
	p := statusFixture(func(p *Provider) {
		p.ready = true
		p.exitCount = 3
		p.client = &fakeClient{exits: []torclient.RouterInfo{
			{Nickname: "a", IDDigest: strings.Repeat("1", 40), Address: "1.2.3.4:9001"},
			{Nickname: "b", IDDigest: strings.Repeat("2", 40), Address: "2.3.4.5:9002"},
		}}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			if _, err := p.Outbounds(context.Background()); err != nil {
				t.Errorf("Outbounds: %v", err)
				return
			}
			_ = p.Status()
		}
	}()
	<-done
}
