// Package tor is the Tor outbound provider plugin for the goose proxy-pool
// engine (github.com/goose-network/goose). It embeds tor-go — a from-scratch
// Go Tor client — as a library and exposes it to goose the same way the
// Psiphon provider embeds tunnel-core: the provider bootstraps a real Tor
// client (directory fetch, guard link, circuit pool) in the background, and
// once the client is connected it emits ONE goose outbound of protocol
// "tor". Dials through that outbound open a Tor circuit IN PROCESS — the
// outbound calls the client's DialStream directly — so there is no SOCKS/HTTP
// hop between goose and the Tor client, and the client's own connections
// (guard link, directory fetches) dial through the engine's layer-3/4 stack.
//
// This package lives inside the tor-go module (not a separate repo) because
// it embeds tor-go's internal packages (internal/torclient, internal/directory),
// which Go's internal-package rule confines to this module. It imports only
// goose-plugin-api on the goose side, preserving the plugin import boundary:
// a plugin imports the contract module, never goose itself.
//
// # Bootstrap lifecycle
//
// A real Tor client must fetch a signed microconsensus + microdescriptors,
// select a guard, and complete a TLS link handshake before it can serve a
// single byte — easily a minute on first run. The provider therefore starts
// tor-go in a background goroutine from the factory (mirroring the Psiphon
// provider's startTunnel): Outbounds returns an empty set until the client
// is connected, then signals Watch so the engine repolls promptly and the
// pool fills in without waiting for the 2-minute fallback poll. A bootstrap
// failure (upstream down, authorities unreachable) is retried with backoff
// in the same goroutine rather than failing the factory, so a temporarily
// dead network does not permanently kill the provider; Outbounds keeps
// returning empty and the pool simply stays empty.
//
// # Config
//
// The provider config is a JSON object:
//
//	{
//	  "upstream_proxy":           "127.0.0.1:7890",  // SOCKS5 to reach relays/authorities
//	  "path_len":                 3,                 // circuit hops (default 3)
//	  "outbound_id":              "tor",             // goose outbound id (default "tor")
//	  "fetch_timeout_seconds":    300,               // directory bootstrap timeout
//	  "max_microdescs":          400,               // cap descriptors (0 = all)
//	  "verify_signatures":        true,               // consensus signature quorum (default true; the
//	                                                   // dirports serve plain HTTP — without this a MITM
//	                                                   // could substitute the consensus)
//	  "use_fallbacks":            false,              // CREATE_FAST fallback bootstrap
//	  "link_dial_timeout_seconds":  45,               // guard TLS link timeout
//	  "circuit_build_timeout_seconds": 90,           // per-circuit build timeout
//	  "allow_private_addresses":  false              // allow private stream targets
//	}
package tor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"sync"
	"time"

	pub "github.com/goose-network/goose-plugin-api"

	"github.com/goose-network/tor-go/internal/directory"
	"github.com/goose-network/tor-go/internal/proxy"
	"github.com/goose-network/tor-go/internal/torclient"
)

func init() {
	pub.RegisterProvider("tor", NewProvider)
}

// streamDialer is the tor-go client surface dialStream needs;
// *torclient.Client implements it. An interface keeps the dial path testable
// without a full Tor bootstrap.
type streamDialer interface {
	DialStream(ctx context.Context, target string) (io.ReadWriteCloser, error)
}

// Provider is a goose outbound provider backed by an embedded tor-go client.
// It implements pub.Provider.
type Provider struct {
	cfg providerConfig

	// client is the running tor-go client, guarded by mu. It is non-nil from
	// the moment a bootstrap attempt creates it until that attempt's Run
	// exits; dials while it is nil or not connected fail fast.
	mu       sync.Mutex
	client   streamDialer
	ready    bool  // client is connected to its guard link
	startErr error // last terminal startup error, surfaced via Outbounds

	// watch signals the engine that the outbound set changed (ready flip).
	watchCh chan struct{}

	// stop cancels the bootstrap/run goroutine; stopWg waits for it.
	stop    context.CancelFunc
	stopped chan struct{} // closed when the goroutine exits
}

// providerConfig is the deserialized provider config map.
type providerConfig struct {
	UpstreamProxy              string `json:"upstream_proxy"`
	PathLen                    int    `json:"path_len"`
	OutboundID                 string `json:"outbound_id"`
	FetchTimeoutSeconds        int    `json:"fetch_timeout_seconds"`
	MaxMicrodescs              int    `json:"max_microdescs"`
	VerifySignatures           *bool  `json:"verify_signatures"`
	UseFallbacks               bool   `json:"use_fallbacks"`
	LinkDialTimeoutSeconds     int    `json:"link_dial_timeout_seconds"`
	CircuitBuildTimeoutSeconds int    `json:"circuit_build_timeout_seconds"`
	AllowPrivateAddresses      bool   `json:"allow_private_addresses"`
}

// NewProvider is the ProviderFactory registered as "tor". It parses the config and
// starts the tor-go client bootstrap in the background; Outbounds returns a
// "tor" protocol outbound once the client is connected, and an empty set
// before.
func NewProvider(cfg map[string]any) (pub.Provider, error) {
	pc, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}
	if pc.OutboundID == "" {
		pc.OutboundID = "tor"
	}
	// verify_signatures defaults ON: the directory authorities' dirports
	// serve plain HTTP, and the signature quorum is the only mechanism that
	// authenticates the consensus (see fetch.go's FetchOptions doc). An
	// explicit "verify_signatures": false opts out.
	if pc.VerifySignatures == nil {
		on := true
		pc.VerifySignatures = &on
	}

	// The engine injects its stack dialer under pub.StackDialerKey; route
	// the client's own connections (guard link, directory fetches, fallback
	// ORPorts, and the upstream SOCKS5 hop itself) through it so the plugin
	// uses the engine's layer-3/4 stack instead of the raw system dialer.
	var linkDialer proxy.Dialer
	if sd := pub.AsStackDialer(cfg); sd != nil {
		linkDialer = sd.Dial
	}

	p := &Provider{
		cfg:     pc,
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.stop = cancel
	go func() {
		defer close(p.stopped)
		p.run(ctx, linkDialer)
	}()
	registerLiveProvider(p)
	return p, nil
}

// dialStream is the in-memory dial entry for the "tor" outbound protocol:
// it opens a Tor circuit and stream to target through the live client. The
// outbound has already applied the target policy (onion, port 0, private).
func (p *Provider) dialStream(ctx context.Context, target string) (net.Conn, error) {
	p.mu.Lock()
	cli := p.client
	p.mu.Unlock()
	if cli == nil {
		return nil, errors.New("tor provider: client not running (bootstrap failed or provider stopped)")
	}
	stream, err := cli.DialStream(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("tor provider: dial %s: %w", target, err)
	}
	return streamConn{stream}, nil
}

func parseConfig(cfg map[string]any) (providerConfig, error) {
	// A nil config map is valid (all defaults); guard json.Marshal(nil).
	// The engine-injected dialer values (func/interface under the reserved
	// "_dialer"/"_upstream_dialer" keys) are ignored here: they are consumed
	// via AsStackDialer above, and json.Marshal would choke on them.
	cfg = maps.Clone(cfg)
	delete(cfg, pub.StackDialerKey)
	delete(cfg, pub.UpstreamDialerKey)
	if cfg == nil {
		return providerConfig{}, nil
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return providerConfig{}, fmt.Errorf("tor provider: marshal config: %w", err)
	}
	var pc providerConfig
	if err := json.Unmarshal(raw, &pc); err != nil {
		return providerConfig{}, fmt.Errorf("tor provider: parse config: %w", err)
	}
	return pc, nil
}

// run bootstraps the tor-go client, retrying with backoff until it is
// connected, then blocks until ctx is cancelled. The client's whole lifetime
// is tied to ctx: cancelling it stops the keep-alive loop, the guard link,
// and the hourly consensus refresh (all derived from it in Run).
func (p *Provider) run(ctx context.Context, linkDialer proxy.Dialer) {
	const maxBackoff = 60 * time.Second
	backoff := 5 * time.Second
	for {
		if err := p.startOnce(ctx, linkDialer); err != nil {
			if ctx.Err() != nil {
				p.setTerminal(err)
				return
			}
			log.Printf("tor provider: bootstrap failed: %v (retrying in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		// startOnce returns only when the client's Run exits (ctx
		// cancelled); nothing left to retry.
		return
	}
}

// startOnce drives one full bootstrap attempt: fetch the directory, start
// the client, and block on its Run loop. It returns a nil error only when
// Run exits cleanly via ctx cancellation.
func (p *Provider) startOnce(ctx context.Context, linkDialer proxy.Dialer) error {
	pc := p.cfg

	// 1. Fetch the directory (consensus + microdescriptors). This is the
	//    slow part: authorities, then one HTTP GET per microdescriptor
	//    digest. Every fetch dials through the engine stack (linkDialer).
	timeout := time.Duration(pc.FetchTimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	fetchCtx, fcancel := context.WithTimeout(ctx, timeout)
	defer fcancel()
	opts := directory.FetchOptions{
		UpstreamProxy:    pc.UpstreamProxy,
		Dialer:           linkDialer,
		Timeout:          timeout,
		MaxMicrodescs:    pc.MaxMicrodescs,
		VerifySignatures: *pc.VerifySignatures,
		UseFallbacks:     pc.UseFallbacks,
	}
	if opts.UseFallbacks {
		// The fallback-circuit bootstrap path (fetchcircuit.go) does not
		// yet verify consensus signatures; never silently downgrade the
		// authentication the caller asked for.
		if opts.VerifySignatures {
			return errors.New("tor provider: use_fallbacks=true does not support verify_signatures=true (fallback bootstrap is unauthenticated); drop one")
		}
	}
	dir, err := directory.Fetch(fetchCtx, opts)
	fcancel()
	if err != nil {
		return fmt.Errorf("fetch directory: %w", err)
	}
	usable := 0
	for _, r := range dir {
		if r.OnionKey != ([32]byte{}) {
			usable++
		}
	}
	if usable == 0 {
		return errors.New("fetched directory has no relays with onion keys")
	}
	log.Printf("tor provider: directory ready: %d relays (%d with onion keys)", len(dir), usable)

	// 2. Build the client config. No SOCKS listener is configured: the
	//    provider dials streams in memory (see dialStream), so tor-go's
	//    Run — unlike Serve — never binds a local proxy port.
	var linkTimeout, circTimeout time.Duration
	if pc.LinkDialTimeoutSeconds > 0 {
		linkTimeout = time.Duration(pc.LinkDialTimeoutSeconds) * time.Second
	}
	if pc.CircuitBuildTimeoutSeconds > 0 {
		circTimeout = time.Duration(pc.CircuitBuildTimeoutSeconds) * time.Second
	}
	tcfg := &torclient.Config{
		PathLen:               pc.PathLen,
		Directory:             dir,
		UpstreamProxy:         pc.UpstreamProxy,
		LinkDialer:            linkDialer,
		LinkDialTimeout:       linkTimeout,
		CircuitBuildTimeout:   circTimeout,
		AllowPrivateAddresses: pc.AllowPrivateAddresses,
		// Refresh the consensus hourly: the engine is a long-lived client
		// and a microconsensus is valid ~3h; without a refresh, descriptor
		// churn (ntor key rotation, relays leaving) would eventually break
		// every circuit build while the outbound stays advertised. Mirrors
		// the C client's re-fetch at fresh-until time.
		RefreshInterval: time.Hour,
		FetchOptions: &directory.FetchOptions{
			UpstreamProxy:    pc.UpstreamProxy,
			Dialer:           linkDialer,
			Timeout:          timeout,
			MaxMicrodescs:    pc.MaxMicrodescs,
			VerifySignatures: *pc.VerifySignatures,
			UseFallbacks:     pc.UseFallbacks,
		},
	}
	cli, err := torclient.New(ctx, tcfg)
	if err != nil {
		return fmt.Errorf("init tor client: %w", err)
	}
	p.mu.Lock()
	p.client = cli
	p.mu.Unlock()

	// 3. Run until cancelled: connect the guard, keep the link alive
	//    (padding + self-healing redial), refresh the consensus hourly. A
	//    Connect failure is returned immediately and retried by the caller.
	runErr := make(chan error, 1)
	go func() {
		runErr <- cli.Run(ctx)
	}()
	if err := p.awaitConnected(ctx, cli, runErr, 15*time.Second); err != nil {
		p.clearClient()
		return fmt.Errorf("guard connection: %w", err)
	}

	// 4. Block until Run exits. Cancelling ctx closes the guard link and
	//    stops the background loops; a Run failure is retried by the caller.
	select {
	case <-ctx.Done():
		<-runErr
		p.clearClient()
		return nil
	case err := <-runErr:
		p.setNotReady()
		p.clearClient()
		return fmt.Errorf("run exited: %w", err)
	}
}

// clearClient drops the client reference so dials fail fast instead of
// hitting a client whose Run loop has exited.
func (p *Provider) clearClient() {
	p.mu.Lock()
	p.client = nil
	p.mu.Unlock()
}

// awaitConnected blocks until the client reports a live guard link, Run
// exits early (connect failure), or the timeout elapses.
func (p *Provider) awaitConnected(ctx context.Context, cli *torclient.Client, runErr <-chan error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-runErr:
			return fmt.Errorf("run exited before connecting: %w", err)
		case <-time.After(100 * time.Millisecond):
		}
		if cli.Connected() {
			p.mu.Lock()
			p.ready = true
			p.mu.Unlock()
			log.Printf("tor provider: tor-go client connected to guard")
			p.signalWatch()
			return nil
		}
	}
	return errors.New("timeout waiting for guard connection")
}

// setTerminal records a startup error and wakes the engine for one final
// poll so Outbounds can surface it; setNotReady drops the outbound.
func (p *Provider) setTerminal(err error) {
	p.mu.Lock()
	p.startErr = err
	p.mu.Unlock()
	p.signalWatch()
}

func (p *Provider) setNotReady() {
	p.mu.Lock()
	p.ready = false
	p.mu.Unlock()
	p.signalWatch()
}

// Name returns the provider plugin name.
func (p *Provider) Name() string { return "tor" }

// Watch returns the change signal channel.
func (p *Provider) Watch() <-chan struct{} { return p.watchCh }

// Outbounds returns the current outbound set: empty until the tor-go client
// is connected, then a single outbound of the "tor" protocol, which dials
// circuits in memory through this provider. A terminal bootstrap failure
// returns the error so the engine logs it (the existing pool, if any, is
// kept).
func (p *Provider) Outbounds(_ context.Context) ([]pub.OutboundConfig, error) {
	p.mu.Lock()
	ready := p.ready
	err := p.startErr
	id := p.cfg.OutboundID
	allowPrivate := p.cfg.AllowPrivateAddresses
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, nil
	}
	return []pub.OutboundConfig{
		{
			ID:       id,
			Protocol: "tor",
			Config: map[string]any{
				"id":            id,
				"tunnel":        id,
				"allow_private": allowPrivate,
			},
		},
	}, nil
}

// Close stops the tor-go client and waits for the goroutine to exit. The
// engine's provider manager calls Close on stopped providers.
func (p *Provider) Close() error {
	unregisterLiveProvider(p)
	if p.stop != nil {
		p.stop()
	}
	<-p.stopped
	p.mu.Lock()
	p.ready = false
	p.client = nil
	p.mu.Unlock()
	return nil
}

// signalWatch notifies the engine (non-blocking) that the outbound set may
// have changed.
func (p *Provider) signalWatch() {
	select {
	case p.watchCh <- struct{}{}:
	default:
	}
}
