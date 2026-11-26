// Package tor is the Tor outbound provider plugin for the goose proxy-pool
// engine (github.com/goose-network/goose). It embeds tor-go — a from-scratch
// Go Tor client — as a library and exposes it to goose the same way the
// Psiphon provider embeds tunnel-core: the provider bootstraps a real Tor
// client (directory fetch, guard link, per-stream circuits) in the background, and
// once the client is connected it emits the goose outbound set — a general
// "tor" outbound plus ONE outbound per Exit-flagged relay in the client's
// directory (the tor analogue of the psiphon provider's per-server list), so
// the engine's web UI can show the real relay roster and any relay can be
// pinned per inbound or pool. Dials through any of these outbounds open a Tor
// circuit IN PROCESS — the outbound calls the client's DialStream directly
// (with the exit hop pinned on per-relay outbounds) — so there is no
// SOCKS/HTTP hop between goose and the Tor client. The client's two connection
// planes are routed separately: the directory fetches that discover the relay
// roster (the control plane) ride the provider's upstream_proxy — an injected
// engine route (a goose outbound/pool/chain) when the spec names one, else the
// config's raw SOCKS5 address over the engine stack — while the guard link
// every circuit rides (the outbounds' data path) rides the engine's
// layer-3/4 stack, or direct when none is injected, by default. The opt-in
// link_via_upstream config key additionally routes the guard link through
// the injected engine route (openrung -> tor) for hosts where direct guard
// dials are blocked; without it the provider upstream never carries the
// data path.
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
// provider's startTunnel). The directory fetch is the server-list source: as
// soon as it completes, Outbounds advertises one outbound per Exit-flagged
// relay — independent of the guard link, like psiphon's datastore server list —
// and adds the general "tor" outbound once the client is connected, signaling
// Watch so the engine repolls promptly without waiting for the 2-minute
// fallback poll. A bootstrap failure (upstream down, authorities unreachable)
// is retried with backoff in the same goroutine rather than failing the
// factory, so a temporarily dead network does not permanently kill the
// provider; the last fetched roster stays advertised meanwhile.
//
// # Config
//
// The provider config is a JSON object:
//
//	{
//	  "upstream_proxy":           "127.0.0.1:7890",  // SOCKS5 for the directory/authority fetches ONLY
//	                                                   // (roster discovery); never routes relay/circuit dials.
//	                                                   // Dropped when a spec-level upstream_proxy names a goose
//	                                                   // route — UNLESS link_via_upstream keeps it for decoupled
//	                                                   // fetches (engine stack + this address, off the route)
//	  "link_via_upstream":        false,             // opt the GUARD LINK into the spec-level injected route too
//	                                                   // (openrung -> tor); no effect without an injected route
//	  "path_len":                 3,                 // circuit hops (default 3)
//	  "outbound_id":              "tor",             // goose outbound id (default "tor")
//	  "fetch_timeout_seconds":    300,               // directory bootstrap timeout
//	  "max_microdescs":          400,               // cap descriptors (0 = all)
//	  "verify_signatures":        true,               // consensus signature quorum (default true; the
//	                                                   // dirports serve plain HTTP — without this a MITM
//	                                                   // could substitute the consensus)
//	  "use_fallbacks":            false,              // CREATE_FAST fallback bootstrap
//	  "link_dial_timeout_seconds":  45,               // guard TLS link timeout
//	  "link_idle_timeout_seconds":  0,               // guard-link rolling read deadline (0 = 120s default);
//	                                                   // expiry redials only under unanswered load (deaf tunnel)
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
	// Zero-config: the embedded directory authorities fetch the relay roster
	// with an empty config map, so the engine auto-seeds a tor provider — it
	// appears in the admin UI without operator setup.
	pub.RegisterDefaultProvider(pub.DefaultProvider{Provider: "tor"})
}

// The provider implements the optional observability contract the engine
// merges into /api/providers/status.
var _ pub.StatusReporter = (*Provider)(nil)

// streamDialer is the tor-go client surface dialStream needs;
// *torclient.Client implements it. An interface keeps the dial path testable
// without a full Tor bootstrap. Per-exit pinning is a separate interface
// (exitLister / exitPinner) the concrete client also implements.
type streamDialer interface {
	DialStream(ctx context.Context, target string) (io.ReadWriteCloser, error)
}

// exitLister reports the relay roster for per-exit outbound emission. It is
// the Provider-facing slice of *torclient.Client's ExitInfos.
type exitLister interface {
	// ExitInfos returns one entry per Exit-flagged relay currently in the
	// directory, keyed by hex identity digest.
	ExitInfos() []torclient.RouterInfo
}

// exitPinner is the dial form behind a per-exit outbound: the circuit's exit
// hop is pinned to the named relay instead of chosen randomly per stream.
type exitPinner interface {
	DialStreamViaExit(ctx context.Context, hexDigest, target string) (io.ReadWriteCloser, error)
}

// statusSource is the client surface Status() reads for live facts: guard
// link liveness, the guard relay circuits ride, and the directory size.
// *torclient.Client implements it; test mocks may not (Status degrades
// gracefully).
type statusSource interface {
	Connected() bool
	Guard() *directory.Router
	RouterCount() int
}

// Provider is a goose outbound provider backed by an embedded tor-go client.
// It implements pub.Provider and pub.StatusReporter.
type Provider struct {
	cfg providerConfig

	// viaRoute records that the engine injected an upstream-route dialer
	// (the spec's upstream_proxy names a goose route), which carries the
	// directory fetches in place of the stack dialer and the config's raw
	// upstream_proxy address. The guard link rides the stack by default; it
	// rides the route too only when link_via_upstream opts in. Surfaced
	// through Status.
	viaRoute bool

	// client is the running tor-go client, guarded by mu. It is non-nil from
	// the moment a bootstrap attempt creates it until that attempt's Run
	// exits; dials while it is nil or not connected fail fast.
	mu       sync.Mutex
	client   streamDialer
	ready    bool  // client is connected to its guard link
	startErr error // last terminal startup error, surfaced via Outbounds

	// Observability state for Status(), all guarded by mu: the bootstrap
	// phase word, retry bookkeeping between attempts, and the directory /
	// roster sizes. They let an operator tell a fetching, connecting,
	// serving, or retrying provider apart from /api/providers/status
	// without reading engine logs — the engine-side lifecycle alone cannot
	// (it sees only "running" plus an empty pool).
	phase       string    // current progress word: "fetching directory", "connecting guard", "running"
	lastBootErr error     // last bootstrap failure; cleared when the client connects
	attempts    int       // bootstrap attempts since the factory
	nextRetry   time.Time // when run() retries after lastBootErr (zero = n/a)
	relays      int       // usable relays in the last fetched directory
	exitCount   int       // exits in the roster at the last Outbounds emission
	connectedAt time.Time // guard link up since
	closed      bool

	// exits is the exit roster snapshotted when a bootstrap attempt creates the
	// client (the directory is fetched by then). It persists across guard-link
	// retries — when client is cleared after a failed guard connection — so the
	// discovered servers stay advertised independent of guard readiness, the
	// tor analogue of psiphon's datastore server list. Guarded by mu.
	exits []torclient.RouterInfo

	// watch signals the engine that the outbound set changed (ready flip).
	watchCh chan struct{}

	// stop cancels the bootstrap/run goroutine; stopWg waits for it.
	stop    context.CancelFunc
	stopped chan struct{} // closed when the goroutine exits
}

// providerConfig is the deserialized provider config map.
type providerConfig struct {
	UpstreamProxy string `json:"upstream_proxy"`
	// LinkViaUpstream opts the GUARD LINK (the data path every circuit rides)
	// into the same engine-injected upstream route as the directory fetches.
	// Default false keeps the documented fetch-only contract: the guard link
	// rides the engine stack / direct, never the route. Set true together with
	// a spec-level upstream_proxy naming an openrung route (outbound:/pool:/
	// chain:) to tunnel tor itself through that route — openrung -> tor — on
	// hosts where direct guard dials are blocked. The route dialer returns a
	// completed tunnel, so the guard TLS + link handshake layer over it
	// unchanged. No effect unless a route is actually injected (viaRoute).
	LinkViaUpstream            bool   `json:"link_via_upstream"`
	PathLen                    int    `json:"path_len"`
	OutboundID                 string `json:"outbound_id"`
	FetchTimeoutSeconds        int    `json:"fetch_timeout_seconds"`
	MaxMicrodescs              int    `json:"max_microdescs"`
	VerifySignatures           *bool  `json:"verify_signatures"`
	UseFallbacks               bool   `json:"use_fallbacks"`
	LinkDialTimeoutSeconds     int    `json:"link_dial_timeout_seconds"`
	CircuitBuildTimeoutSeconds int    `json:"circuit_build_timeout_seconds"`
	// LinkIdleTimeoutSeconds is the guard link's rolling first-byte read
	// deadline: on expiry the link is redialed only if real circuit cells are
	// being sent unanswered (a deaf upstream tunnel); a healthy idle link is
	// kept. Zero uses tor-go's generous default (120s).
	LinkIdleTimeoutSeconds int  `json:"link_idle_timeout_seconds"`
	AllowPrivateAddresses  bool `json:"allow_private_addresses"`
}

// engineStackDialer picks the DEFAULT dialer tor-go's guard link dials through
// — the outbounds' data path: the engine's layer-3/4 stack dialer when injected,
// else nil (tor-go's own system dialer). It deliberately never consults the
// upstream route: the provider's upstream_proxy scopes the roster fetches only,
// not the relay connection every circuit rides. resolvePlanes overrides this
// default with the route dialer ONLY when the operator opts in via
// link_via_upstream (see there); absent that knob the guard link stays on the
// stack / direct, preserving the fetch-only contract.
func engineStackDialer(cfg map[string]any) proxy.Dialer {
	if sd := pub.AsStackDialer(cfg); sd != nil {
		return sd.Dial
	}
	return nil
}

// systemDialer dials directly via the host network stack. It is the fetch-plane
// fallback when no engine stack dialer was injected (route-only embedding), so a
// decoupled directory fetch never falls back to the guard-link route dialer.
func systemDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// engineFetchDialer picks the dialer tor-go's directory fetches ride — the
// control plane that discovers the relay roster: the engine-injected route
// dialer when the provider spec's upstream_proxy names a goose route
// (outbound:/pool:/chain:), else the engine's stack dialer (with the config's
// raw upstream_proxy SOCKS5 address chained on top by FetchOptions), else nil
// (tor-go's own dialer). The second return reports whether a route was chosen,
// i.e. whether it supersedes the plugin config's raw upstream_proxy address.
func engineFetchDialer(cfg map[string]any) (proxy.Dialer, bool) {
	if ud := pub.AsUpstreamDialer(cfg); ud != nil {
		return ud.DialUpstream, true
	}
	if sd := pub.AsStackDialer(cfg); sd != nil {
		return sd.Dial, false
	}
	return nil, false
}

// dialPlanes carries the two connection planes resolvePlanes builds from the
// engine-injected dialers: link dials the guard connection every circuit rides
// (the data path — engine stack or direct by default, the injected upstream
// route only when link_via_upstream opts in); fetch dials the directory/
// authority connections that discover the roster (the control plane — the
// injected upstream route, else the stack with the config's raw upstream_proxy
// SOCKS5 hop on top).
type dialPlanes struct {
	link  proxy.Dialer
	fetch proxy.Dialer
}

// resolvePlanes splits the engine-injected dialers by plane and applies the
// opt-in link_via_upstream knob, mutating pc.UpstreamProxy when a route
// supersedes the raw fetch address. By default the guard link (data path) rides
// the engine stack or direct and NEVER the upstream route — the fetch-only
// contract. When the spec's upstream_proxy names a goose route (viaRoute) AND
// link_via_upstream is set, the guard link rides that same route dialer too:
// DialUpstream returns a completed tunnel to the guard OR address, so tor-go's
// TLS + v3 link handshake and every circuit multiplexed on the link layer over
// it unchanged. This is what carries tor through openrung (openrung -> tor) on
// a censored host where direct guard dials are blocked. The knob is a no-op
// without an injected route, so upstream_proxy="" keeps the guard link direct.
// When link_via_upstream is set AND a raw config upstream_proxy address is also
// present, the fetch plane is decoupled: fetches ride the engine stack + that
// raw SOCKS5 address while the guard link rides the route, so a deaf upstream
// tunnel cannot stall roster discovery.
func resolvePlanes(cfg map[string]any, pc *providerConfig) (dialPlanes, bool) {
	d := dialPlanes{link: engineStackDialer(cfg)}
	fetch, viaRoute := engineFetchDialer(cfg)
	d.fetch = fetch
	if viaRoute {
		if pc.LinkViaUpstream {
			// Opt-in: carry the guard link through the same route as the
			// fetches. d.fetch is the route dialer (ud.DialUpstream) here,
			// whose signature already matches proxy.Dialer.
			d.link = fetch
			if pc.UpstreamProxy != "" {
				// Fetch decoupling: the operator supplied a raw SOCKS5 address
				// (e.g. a local Clash) alongside link_via_upstream. Keep the
				// directory/authority fetches on the engine stack + that raw
				// address instead of the injected route, so the roster-discovery
				// control plane does NOT ride the same upstream tunnel as the
				// guard link — a deaf or slow openrung tunnel then cannot stall
				// the consensus fetch (the partial-roster failure mode). The raw
				// address only ever feeds FetchOptions; the link plane's
				// Config.UpstreamProxy stays empty, so it never leaks onto a
				// relay dial.
				d.fetch = engineStackDialer(cfg)
				if d.fetch == nil {
					// Route-only embedding (no stack dialer injected). Never leave
					// the fetch dialer nil: torclient.fetchOpts falls back to
					// cfg.LinkDialer (the ROUTE) for a nil Dialer, which would
					// re-couple the hourly consensus refresh to the upstream tunnel
					// and chain the raw SOCKS5 address inside it. An explicit system
					// dialer keeps decoupled fetches off the route.
					d.fetch = systemDialer
				}
			} else {
				// No raw address: fetches ride the route too. Drop the (empty)
				// raw address so the fetchOpts fallback never chains a hop.
				pc.UpstreamProxy = ""
			}
		} else {
			// Fetch-only contract: the route supersedes the plugin config's raw
			// upstream_proxy address for the fetches — tor-go would otherwise
			// chain a SOCKS5 hop INSIDE the engine route (double-proxying through
			// a raw address the operator probably meant to replace) — so the raw
			// address is dropped and the route dials the authorities directly.
			pc.UpstreamProxy = ""
		}
	}
	return d, viaRoute
}

// NewProvider is the ProviderFactory registered as "tor". It parses the config and
// starts the tor-go client bootstrap in the background; Outbounds advertises the
// discovered exit roster as soon as the directory is fetched (independent of the
// guard link) and adds the general "tor" outbound once the client connects.
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

	// The engine injects its dialers into the config map: the stack dialer
	// under pub.StackDialerKey, and — when the provider spec's
	// upstream_proxy names a goose route (outbound:/pool:/chain:) — the
	// route dialer under pub.UpstreamDialerKey. resolvePlanes splits them by
	// plane and applies the opt-in link_via_upstream knob.
	d, viaRoute := resolvePlanes(cfg, &pc)

	p := &Provider{
		cfg:      pc,
		viaRoute: viaRoute,
		watchCh:  make(chan struct{}, 1),
		stopped:  make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.stop = cancel
	go func() {
		defer close(p.stopped)
		p.run(ctx, d)
	}()
	registerLiveProvider(p)
	return p, nil
}

// dialStream is the in-memory dial entry for the "tor" outbound protocol:
// it opens a Tor circuit and stream to target through the live client. The
// outbound has already applied the target policy (onion, port 0, private).
func (p *Provider) dialStream(ctx context.Context, target string) (net.Conn, error) {
	return p.dialStreamExit(ctx, "", target)
}

// dialStreamExit is dialStream with the circuit's exit hop optionally pinned
// to one relay (hex identity digest; empty = random exit per stream). Dials
// through a per-exit outbound land here with the digest that outbound
// carries.
func (p *Provider) dialStreamExit(ctx context.Context, exitDigest, target string) (net.Conn, error) {
	p.mu.Lock()
	cli := p.client
	p.mu.Unlock()
	if cli == nil {
		return nil, errors.New("tor provider: client not running (bootstrap failed or provider stopped)")
	}
	var stream io.ReadWriteCloser
	var err error
	if exitDigest == "" {
		stream, err = cli.DialStream(ctx, target)
	} else {
		pinner, ok := cli.(exitPinner)
		if !ok {
			return nil, errors.New("tor provider: client does not support pinned-exit dials")
		}
		stream, err = pinner.DialStreamViaExit(ctx, exitDigest, target)
	}
	if err != nil {
		return nil, fmt.Errorf("tor provider: dial %s: %w", target, err)
	}
	return streamConn{stream}, nil
}

// exitAddress reports the OR address of the relay named by exitDigest in the
// live client's current exit roster. Per-relay outbounds expose it as their
// Address so the engine can display, geolocate, and probe the real relay.
func (p *Provider) exitAddress(exitDigest string) (string, error) {
	p.mu.Lock()
	cli := p.client
	p.mu.Unlock()
	lister, ok := cli.(exitLister)
	if !ok {
		return "", errors.New("tor provider: client has no exit roster")
	}
	for _, r := range lister.ExitInfos() {
		if r.IDDigest == exitDigest {
			return r.Address, nil
		}
	}
	return "", fmt.Errorf("tor provider: exit %s is not in the current roster", exitDigest)
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
func (p *Provider) run(ctx context.Context, d dialPlanes) {
	const maxBackoff = 60 * time.Second
	backoff := 5 * time.Second
	for {
		if err := p.startOnce(ctx, d); err != nil {
			if ctx.Err() != nil {
				p.setTerminal(err)
				return
			}
			retryAt := time.Now().Add(backoff)
			p.recordBootFailure(err, retryAt)
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
func (p *Provider) startOnce(ctx context.Context, d dialPlanes) error {
	pc := p.cfg
	p.setPhase("fetching directory")

	// 1. Fetch the directory (consensus + microdescriptors). This is the
	//    slow part: authorities, then one HTTP GET per microdescriptor
	//    digest. Every fetch rides the control-plane dialer (d.fetch: the
	//    injected route, else the engine stack) with the config's raw
	//    upstream_proxy SOCKS5 hop chained on top when no route was injected.
	timeout := time.Duration(pc.FetchTimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	fetchCtx, fcancel := context.WithTimeout(ctx, timeout)
	defer fcancel()
	opts := directory.FetchOptions{
		UpstreamProxy:    pc.UpstreamProxy,
		Dialer:           d.fetch,
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
	p.mu.Lock()
	p.relays = usable
	p.mu.Unlock()
	p.setPhase("connecting guard")
	log.Printf("tor provider: directory ready: %d relays (%d with onion keys)", len(dir), usable)

	// 2. Build the client config. No SOCKS listener is configured: the
	//    provider dials streams in memory (see dialStream), so tor-go's
	//    Run — unlike Serve — never binds a local proxy port.
	tcfg := p.clientConfig(dir, d, timeout)
	cli, err := torclient.New(ctx, tcfg)
	if err != nil {
		return fmt.Errorf("init tor client: %w", err)
	}
	p.mu.Lock()
	p.client = cli
	// Snapshot the discovered exit roster now: the directory is loaded, so it
	// is available before the guard link connects. Outbounds advertises it
	// independent of guard readiness (like psiphon's datastore server list),
	// and the snapshot survives a failed guard attempt clearing client, so the
	// servers stay listed while run() retries the bootstrap.
	p.exits = cli.ExitInfos()
	p.mu.Unlock()
	p.signalWatch()

	// 3. Run until cancelled: connect the guard, keep the link alive
	//    (padding + self-healing redial), refresh the consensus hourly. A
	//    Connect failure is returned immediately and retried by the caller.
	//    Run rides a per-attempt ctx: an attempt abandoned by the await
	//    window is cancelled and reaped, never left as a zombie client that
	//    connects later and holds a guard tunnel (and an upstream-route
	//    tunnel) nobody dials through.
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	runErr := make(chan error, 1)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		runErr <- cli.Run(runCtx)
	}()
	// The await window must cover the WHOLE prop271 failover sequence (up to
	// GuardConnectAttempts guards, each its own LinkDialTimeout): a route-borne
	// connect (link_via_upstream) failing over past deaf guards is slower than a
	// LAN stack dial, and a window sized for one dial would reap it mid-sequence.
	// torclient.New normalized tcfg.LinkDialTimeout (30s default).
	if err := p.awaitConnected(ctx, cli, runErr, guardAwaitWindow(tcfg.LinkDialTimeout)); err != nil {
		runCancel()
		<-runDone // Run exits, closing any link it established; no zombie
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

// clientConfig builds the tor-go client config for one bootstrap attempt. The
// guard link — the outbounds' data path — rides d.link with UpstreamProxy left
// empty, so no SOCKS5 hop is ever chained onto a relay dial. d.link is the
// engine stack / direct by default, or the injected upstream route dialer when
// link_via_upstream opted in (resolvePlanes): that dialer already returns a
// completed tunnel, so the guard TLS + link handshake run over it directly. The
// provider upstream is scoped to FetchOptions, which carries the directory/
// authority fetches (the roster-discovery control plane) and the hourly
// consensus refresh: the injected route dialer, else the stack with the
// config's raw upstream_proxy address.
func (p *Provider) clientConfig(dir map[string]*directory.Router, d dialPlanes, timeout time.Duration) *torclient.Config {
	pc := p.cfg
	var linkTimeout, circTimeout time.Duration
	if pc.LinkDialTimeoutSeconds > 0 {
		linkTimeout = time.Duration(pc.LinkDialTimeoutSeconds) * time.Second
	}
	if pc.CircuitBuildTimeoutSeconds > 0 {
		circTimeout = time.Duration(pc.CircuitBuildTimeoutSeconds) * time.Second
	}
	return &torclient.Config{
		PathLen:               pc.PathLen,
		Directory:             dir,
		LinkDialer:            d.link,
		LinkDialTimeout:       linkTimeout,
		CircuitBuildTimeout:   circTimeout,
		LinkIdleTimeout:       time.Duration(pc.LinkIdleTimeoutSeconds) * time.Second,
		AllowPrivateAddresses: pc.AllowPrivateAddresses,
		// Refresh the consensus hourly: the engine is a long-lived client
		// and a microconsensus is valid ~3h; without a refresh, descriptor
		// churn (ntor key rotation, relays leaving) would eventually break
		// every circuit build while the outbound stays advertised. Mirrors
		// the C client's re-fetch at fresh-until time.
		RefreshInterval: time.Hour,
		FetchOptions: &directory.FetchOptions{
			UpstreamProxy:    pc.UpstreamProxy,
			Dialer:           d.fetch,
			Timeout:          timeout,
			MaxMicrodescs:    pc.MaxMicrodescs,
			VerifySignatures: *pc.VerifySignatures,
			UseFallbacks:     pc.UseFallbacks,
		},
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
			p.phase = "running"
			p.connectedAt = time.Now()
			p.lastBootErr = nil
			p.mu.Unlock()
			log.Printf("tor provider: tor-go client connected to guard")
			p.signalWatch()
			return nil
		}
	}
	return errors.New("timeout waiting for guard connection")
}

// guardAwaitWindow derives the awaitConnected window from the effective
// guard-link dial timeout times the FULL prop271 failover budget, plus margin,
// floored at the legacy 15s so fast LAN bootstraps keep their quick failure
// detection. Connect tries up to torclient.GuardConnectAttempts distinct guards,
// each bounded by its own LinkDialTimeout; a route-borne connect (link_via_upstream)
// failing over past deaf guards can take the whole sequence, so a window sized for
// only ONE dial would reap a slow-but-successful Connect mid-failover and orphan
// the client (then re-fetch the directory and restart selection from scratch).
func guardAwaitWindow(linkTimeout time.Duration) time.Duration {
	w := time.Duration(torclient.GuardConnectAttempts)*linkTimeout + 5*time.Second
	if w < 15*time.Second {
		w = 15 * time.Second
	}
	return w
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

// setPhase records the bootstrap progress word surfaced as Status's message
// while the provider is not yet serving.
func (p *Provider) setPhase(phase string) {
	p.mu.Lock()
	p.phase = phase
	p.mu.Unlock()
}

// recordBootFailure notes the failure that ended the last bootstrap attempt
// and when run() will try again, so Status can explain an empty pool with
// "retrying after <error>" instead of an unspeaking "running" entry.
func (p *Provider) recordBootFailure(err error, retryAt time.Time) {
	p.mu.Lock()
	p.lastBootErr = err
	p.attempts++
	p.nextRetry = retryAt
	p.mu.Unlock()
}

// Status reports the provider's live self-assessment for the engine's
// provider-observability view (pub.StatusReporter): bootstrap phase and
// retry state while the pool is still empty, the guard link and guard relay
// once serving, plus the directory and roster sizes and the config knobs an
// operator needs to interpret them. Pure in-memory reads — safe for the
// engine to poll alongside Outbounds.
func (p *Provider) Status() pub.ProviderStatus {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Config echo knobs; VerifySignatures defaults on (the factory always
	// materializes it, but Status must not panic on a zero-value struct).
	verify := true
	if p.cfg.VerifySignatures != nil {
		verify = *p.cfg.VerifySignatures
	}
	// Echo the effective path length: torclient.New normalizes an unset (0)
	// PathLen to 3, so report 3 rather than the raw 0 the config carries.
	pathLen := p.cfg.PathLen
	if pathLen == 0 {
		pathLen = 3
	}
	details := map[string]any{
		"upstream_proxy":    p.cfg.UpstreamProxy != "",           // raw SOCKS5 upstream for the directory fetches
		"engine_route":      p.viaRoute,                          // injected route carries the directory fetches
		"link_via_upstream": p.viaRoute && p.cfg.LinkViaUpstream, // guard link (data path) rides the injected route too
		"verify_signatures": verify,
		"use_fallbacks":     p.cfg.UseFallbacks,
		"path_len":          pathLen,
		"relays":            p.relays,
		"exits_in_roster":   p.exitCount,
	}
	// Live client facts when the client surface allows them; the bootstrap
	// fetch's count stands in for relays before a client exists.
	if src, ok := p.client.(statusSource); ok {
		if rc := src.RouterCount(); rc > 0 {
			details["relays"] = rc
		}
		details["guard_link_alive"] = src.Connected()
		if g := src.Guard(); g != nil {
			details["guard"] = g.Nickname + " (" + g.Address + ")"
		}
	}
	if !p.connectedAt.IsZero() {
		details["connected_since"] = p.connectedAt.UTC().Format(time.RFC3339)
	}

	st := pub.ProviderStatus{Details: details}
	switch {
	case p.closed:
		st.State = "stopped"
	case p.startErr != nil:
		st.State = "error"
		st.Message = p.startErr.Error()
	case p.ready:
		st.State = "running"
	default:
		// Not serving: an attempt is either underway or scheduled. Surface
		// which, with the progress word / failure / backoff tick.
		details["attempts"] = p.attempts
		if p.lastBootErr != nil {
			st.State = "retrying"
			st.Message = p.lastBootErr.Error()
			if !p.nextRetry.IsZero() {
				details["next_retry_at"] = p.nextRetry.UTC().Format(time.RFC3339)
			}
		} else {
			st.State = "bootstrapping"
			st.Message = p.phase
		}
	}
	return st
}

// Name returns the provider plugin name.
func (p *Provider) Name() string { return "tor" }

// Watch returns the change signal channel.
func (p *Provider) Watch() <-chan struct{} { return p.watchCh }

// Outbounds returns the current outbound set: one outbound per Exit-flagged
// relay in the fetched directory — the tor equivalent of the psiphon provider's
// per-server list — advertised as soon as the directory is retrieved,
// independent of guard-link readiness, so the engine (and the web UI) can show
// and pin the real relay roster zero-config. The general "tor" outbound (random
// exit per circuit, riding a live guard link) is added once the client is
// connected. Per-exit outbounds are named <id>-<nickname>-<digest-prefix>-<ip:port>
// — the relay's OR address is part of the id so it shows which server the
// outbound pins — and pin the circuit's exit hop to that relay via the "exit"
// config key. A terminal bootstrap failure returns the error so the engine logs
// it (the existing pool, if any, is kept).
func (p *Provider) Outbounds(_ context.Context) ([]pub.OutboundConfig, error) {
	p.mu.Lock()
	ready := p.ready
	err := p.startErr
	cli := p.client
	id := p.cfg.OutboundID
	allowPrivate := p.cfg.AllowPrivateAddresses
	snapshot := append([]torclient.RouterInfo(nil), p.exits...)
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}

	// The exit roster is advertised as soon as the directory is fetched,
	// independent of guard-link readiness — like psiphon emitting its datastore
	// servers without waiting for the main tunnel. Prefer the live client's
	// roster (fresh across the hourly consensus refresh) when it is up; else
	// fall back to the snapshot taken at fetch time, which persists across
	// guard-link retries so the discovered servers stay listed.
	exits := snapshot
	if cli != nil {
		if lister, ok := cli.(exitLister); ok {
			exits = lister.ExitInfos()
		}
	}
	// Cache the roster size for Status() so the observability poll stays a
	// field read instead of re-walking the directory here.
	p.mu.Lock()
	p.exitCount = len(exits)
	p.mu.Unlock()

	// The general "tor" outbound rides a live circuit, so it is added only once
	// the guard link is up; the per-exit list represents the discovered relays.
	var out []pub.OutboundConfig
	if ready {
		out = append(out, pub.OutboundConfig{
			ID:       id,
			Protocol: "tor",
			Config: map[string]any{
				"id":            id,
				"tunnel":        id,
				"allow_private": allowPrivate,
			},
		})
	}
	seen := make(map[string]bool, len(exits))
	for _, r := range exits {
		// Append the relay's OR address (ip:port) so the id itself carries
		// the server it pins; the nickname + truncated digest keep it stable
		// across refreshes. Colons in ids are safe (the subscription plugin
		// already emits host:port ids).
		base := id + "-" + r.Nickname + "-" + r.IDDigest[:12] + "-" + r.Address
		exitID := base
		// The truncated digest plus address already make the id unique;
		// guard the rare collision with a numeric suffix so the engine never
		// sees duplicate outbound ids.
		for n := 2; seen[exitID]; n++ {
			exitID = fmt.Sprintf("%s-%d", base, n)
		}
		seen[exitID] = true
		out = append(out, pub.OutboundConfig{
			ID:       exitID,
			Protocol: "tor",
			Config: map[string]any{
				"id":            exitID,
				"tunnel":        id,
				"allow_private": allowPrivate,
				"exit":          r.IDDigest,
				"exit_name":     r.Nickname,
				"address":       r.Address,
			},
		})
	}
	return out, nil
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
	p.closed = true
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
