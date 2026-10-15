// Package tor is the Tor outbound provider plugin for the goose proxy-pool
// engine (github.com/goose-network/goose). It embeds tor-go — a from-scratch
// Go Tor client — as a library and exposes it to goose the same way the
// Psiphon provider embeds tunnel-core: the provider bootstraps a real Tor
// client (directory fetch, guard link, SOCKS5 listener) in the background,
// and once the client is serving it emits ONE goose outbound of protocol
// "socks5" pointing at tor-go's loopback SOCKS5 listener. The engine merges
// that outbound into the provider's managed pool, so any goose inbound
// routed through the pool forwards traffic over real Tor circuits.
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
// is listening, then signals Watch so the engine repolls promptly and the
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
//	  "socks_listen":             "127.0.0.1:0",     // tor-go's own listener (default ephemeral)
//	  "outbound_id":              "tor",             // goose outbound id (default "tor")
//	  "fetch_timeout_seconds":    300,               // directory bootstrap timeout
//	  "max_microdescs":          400,               // cap descriptors (0 = all)
//	  "verify_signatures":        true,               // consensus signature quorum (default true; the
//	                                                   // dirports serve plain HTTP — without this a MITM
//	                                                   // could substitute the consensus)
//	  "use_fallbacks":            false,             // CREATE_FAST fallback bootstrap
//	  "link_dial_timeout_seconds":  45,               // guard TLS link timeout
//	  "circuit_build_timeout_seconds": 90,           // per-circuit build timeout
//	  "allow_private_addresses":  false              // allow private SOCKS targets
//	}
package tor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	pub "github.com/goose-network/goose-plugin-api"

	"github.com/proxy/tor-go/internal/directory"
	"github.com/proxy/tor-go/internal/torclient"
)

func init() {
	pub.RegisterProvider("tor", New)
}

// Provider is a goose outbound provider backed by an embedded tor-go client.
// It implements pub.Provider.
type Provider struct {
	cfg providerConfig

	// client state, guarded by mu
	mu       sync.Mutex
	listenOn string // the address tor-go's SOCKS5 listener accepted
	ready    bool   // listener is up and routable
	startErr error  // last terminal startup error, surfaced via Outbounds

	// watch signals the engine that the outbound set changed (ready flip).
	watchCh chan struct{}

	// stop cancels the bootstrap/serve goroutine; stopWg waits for it.
	stop    context.CancelFunc
	stopped chan struct{} // closed when the goroutine exits
}

// providerConfig is the deserialized provider config map.
type providerConfig struct {
	UpstreamProxy              string `json:"upstream_proxy"`
	PathLen                    int    `json:"path_len"`
	SocksListen                string `json:"socks_listen"`
	OutboundID                 string `json:"outbound_id"`
	FetchTimeoutSeconds        int    `json:"fetch_timeout_seconds"`
	MaxMicrodescs              int    `json:"max_microdescs"`
	VerifySignatures           *bool  `json:"verify_signatures"`
	UseFallbacks               bool   `json:"use_fallbacks"`
	LinkDialTimeoutSeconds     int    `json:"link_dial_timeout_seconds"`
	CircuitBuildTimeoutSeconds int    `json:"circuit_build_timeout_seconds"`
	AllowPrivateAddresses      bool   `json:"allow_private_addresses"`
}

// New is the ProviderFactory registered as "tor". It parses the config and
// starts the tor-go client bootstrap in the background; Outbounds returns a
// socks5 outbound once the client's listener is up, and an empty set before.
func New(cfg map[string]any) (pub.Provider, error) {
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

	p := &Provider{
		cfg:     pc,
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.stop = cancel
	go func() {
		defer close(p.stopped)
		p.run(ctx)
	}()
	return p, nil
}

func parseConfig(cfg map[string]any) (providerConfig, error) {
	// A nil config map is valid (all defaults); guard json.Marshal(nil).
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
// serving, then blocks until ctx is cancelled. The client's whole lifetime is
// tied to ctx: cancelling it stops the SOCKS5 listener, the keep-alive loop,
// the guard link, and the hourly consensus refresh (all derived from it in
// Serve).
func (p *Provider) run(ctx context.Context) {
	const maxBackoff = 60 * time.Second
	backoff := 5 * time.Second
	for {
		if err := p.startOnce(ctx); err != nil {
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
		// startOnce returns only when the client's Serve exits (ctx
		// cancelled or the listener failed); nothing left to retry.
		return
	}
}

// startOnce drives one full bootstrap attempt: fetch the directory, start
// the client listening, and block on its Serve loop. It returns a nil error
// only when Serve exits cleanly via ctx cancellation.
func (p *Provider) startOnce(ctx context.Context) error {
	pc := p.cfg

	// 1. Fetch the directory (consensus + microdescriptors) through the
	//    upstream proxy. This is the slow part: authorities, then one HTTP
	//    GET per microdescriptor digest.
	timeout := time.Duration(pc.FetchTimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	fetchCtx, fcancel := context.WithTimeout(ctx, timeout)
	defer fcancel()
	opts := directory.FetchOptions{
		UpstreamProxy:    pc.UpstreamProxy,
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

	// 2. Build the client config. Requesting "127.0.0.1:0" (the default)
	//    binds an ephemeral loopback port; the actual address is read back
	//    from the listener once Serve binds it.
	listen := p.cfg.SocksListen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	var linkTimeout, circTimeout time.Duration
	if pc.LinkDialTimeoutSeconds > 0 {
		linkTimeout = time.Duration(pc.LinkDialTimeoutSeconds) * time.Second
	}
	if pc.CircuitBuildTimeoutSeconds > 0 {
		circTimeout = time.Duration(pc.CircuitBuildTimeoutSeconds) * time.Second
	}
	tcfg := &torclient.Config{
		SocksAddr:             listen,
		PathLen:               pc.PathLen,
		Directory:             dir,
		UpstreamProxy:         pc.UpstreamProxy,
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

	// 3. Serve until cancelled. Serve binds the listener, so the expected
	//    address can only be resolved after it's up; poll the listener
	//    surface from the client.
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- cli.Serve(ctx)
	}()
	if err := p.awaitListener(ctx, cli, serveErr, 15*time.Second); err != nil {
		return fmt.Errorf("listener startup: %w", err)
	}

	// 4. Block until Serve exits. Cancelling ctx stops the listener and
	//    closes the guard link; a Serve failure (e.g. bind error) is
	//    retried by the caller.
	select {
	case <-ctx.Done():
		<-serveErr
		return nil
	case err := <-serveErr:
		p.setNotReady()
		return fmt.Errorf("serve exited: %w", err)
	}
}

// awaitListener blocks until the client's SOCKS5 listener answers on its
// bound address or the timeout elapses. The listener binds inside Serve, so
// the actual address is read back from the client rather than assumed. If
// Serve exits early (guard connect or bind failure) its error is returned
// immediately instead of spinning until the timeout.
func (p *Provider) awaitListener(ctx context.Context, cli *torclient.Client, serveErr <-chan error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-serveErr:
			return fmt.Errorf("serve exited before listening: %w", err)
		case <-time.After(100 * time.Millisecond):
		}
		addr := cli.SocksAddr()
		if addr == "" {
			continue
		}
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			p.mu.Lock()
			p.listenOn = addr
			p.ready = true
			p.mu.Unlock()
			log.Printf("tor provider: tor-go SOCKS5 listener up at %s", addr)
			p.signalWatch()
			return nil
		}
	}
	return errors.New("timeout waiting for SOCKS5 listener")
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
// is listening, then a single socks5 outbound pointing at its loopback
// SOCKS5 listener. A terminal bootstrap failure returns the error so the
// engine logs it (the existing pool, if any, is kept).
func (p *Provider) Outbounds(_ context.Context) ([]pub.OutboundConfig, error) {
	p.mu.Lock()
	ready := p.ready
	addr := p.listenOn
	err := p.startErr
	id := p.cfg.OutboundID
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ready || addr == "" {
		return nil, nil
	}
	return []pub.OutboundConfig{
		{
			ID:       id,
			Protocol: "socks5",
			Config: map[string]any{
				"id":      id,
				"address": addr,
			},
		},
	}, nil
}

// Close stops the tor-go client and waits for the goroutine to exit. The
// engine's provider manager does not call Close on providers; this exists
// for embedders and tests that manage the provider lifecycle themselves.
func (p *Provider) Close() error {
	if p.stop != nil {
		p.stop()
	}
	<-p.stopped
	p.mu.Lock()
	p.ready = false
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
