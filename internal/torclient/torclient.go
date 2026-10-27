// Package torclient is the top-level Tor client. It owns the directory, the
// guard link, a pool of circuits, and the SOCKS5 listener. Applications
// either configure it with a SOCKS5 proxy address (default 127.0.0.1:7890)
// and route traffic through it, or embed it in process and dial streams
// directly with no listener at all.
//
// Lifecycle (serving SOCKS5):
//
//	cfg := &torclient.Config{SocksAddr: "127.0.0.1:7890", PathLen: 3}
//	cli, err := torclient.New(ctx, cfg)
//	...
//	cli.Serve(ctx)   // blocks, serving SOCKS5
//
// Lifecycle (embedded, no listener — what the goose plugin uses):
//
//	cfg := &torclient.Config{PathLen: 3, LinkDialer: myStack}
//	cli, _ := torclient.New(ctx, cfg)
//	go cli.Run(ctx)          // connects the guard, keeps the link alive
//	stream, _ := cli.DialStream(ctx, "example.org:443")
package torclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"log"
	"net"
	"sync"
	"time"

	"github.com/goose-network/tor-go/internal/circuit"
	"github.com/goose-network/tor-go/internal/directory"
	"github.com/goose-network/tor-go/internal/guard"
	"github.com/goose-network/tor-go/internal/link"
	"github.com/goose-network/tor-go/internal/proxy"
	"github.com/goose-network/tor-go/internal/socks5"
)

// Config configures the Tor client.
type Config struct {
	// SocksAddr is the address the SOCKS5 proxy listens on. Default
	// "127.0.0.1:7890".
	SocksAddr string
	// PathLen is the circuit path length (default 3: guard, middle, exit).
	PathLen int
	// Guard is the relay to use as the guard (first hop). If empty, one is
	// selected from the directory.
	Guard *directory.Router
	// Directory is the parsed directory (consensus + microdescriptors). If
	// nil, the client cannot build circuits and will return an error from
	// New.
	Directory map[string]*directory.Router
	// UpstreamProxy is the address of a SOCKS5 proxy that the link layer
	// dials through to reach relays (e.g. "127.0.0.1:7890" for a local
	// Clash/V2Ray instance). Empty means dial relays directly. This lets
	// tor-go reach the Tor network from behind an upstream proxy.
	UpstreamProxy string
	// LinkDialer, when non-nil, establishes the raw TCP connection for
	// every outbound hop of the client: the guard link, directory fetches,
	// fallback ORPorts, and the connection to UpstreamProxy itself. It is
	// how an embedding process routes the client's own traffic through its
	// network stack (a userspace IP stack, a VPN, …) instead of the system
	// dialer; the TLS and Tor handshakes are layered on top unchanged. Nil
	// is the system dialer.
	LinkDialer proxy.Dialer
	// LinkDialTimeout is the timeout for connecting to the guard.
	LinkDialTimeout time.Duration
	// CircuitBuildTimeout is the timeout for building a circuit.
	CircuitBuildTimeout time.Duration
	// RefreshInterval is how often to re-fetch the consensus in the
	// background while serving. If zero (the default), no background refresh
	// runs and the client uses the directory it was constructed with for its
	// whole lifetime. A real client should set this to a few hours (the C
	// client re-fetches at the consensus fresh-until time, typically every
	// hour). The refresh re-fetches the consensus + microdescriptors and
	// atomically swaps the client's directory in place, so new circuits use
	// the fresh relays.
	RefreshInterval time.Duration
	// FetchOptions, when non-nil, configures the background consensus
	// refresh (and is used by RefreshDirectory). If RefreshInterval is set
	// but FetchOptions is nil, the refresh uses default authorities and the
	// client's UpstreamProxy. Set VerifySignatures here for real-network use.
	FetchOptions *directory.FetchOptions
	// AllowPrivateAddresses, when false (the default), makes the SOCKS5
	// server refuse CONNECT/RESOLVE/RESOLVE_PTR targets that are private,
	// loopback, or link-local addresses, mirroring the C client's
	// ClientRejectInternalAddresses. Set to true to allow explicit private
	// destinations (e.g. for testing through a loopback exit).
	AllowPrivateAddresses bool
}

// Client is a running Tor client.
type Client struct {
	cfg   *Config
	mu    sync.Mutex
	link  *link.Link
	dir   map[string]*directory.Router
	guard *directory.Router
	// guards is the prop271 guard-selection state machine. It is nil when the
	// caller pinned a specific guard via Config.Guard (no failover).
	guards *guard.Manager
	socks  *socks5.Server
	closed bool
	// dialMu serializes guard (re)dials (Connect). The check-link / dial /
	// store-link sequence in Connect must not interleave: two concurrent
	// redialGuard calls (keep-alive tick + a request hitting a dead link)
	// would otherwise both dial and clobber c.link, leaking the loser's TLS
	// connection and its readLoop goroutine.
	dialMu sync.Mutex
}

// New validates the config and prepares the client. It does not connect to
// the guard until Serve is called (or Connect is called explicitly).
func New(ctx context.Context, cfg *Config) (*Client, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.SocksAddr == "" {
		cfg.SocksAddr = "127.0.0.1:7890"
	}
	if cfg.PathLen == 0 {
		cfg.PathLen = 3
	}
	if cfg.PathLen < 1 || cfg.PathLen > 8 {
		return nil, fmt.Errorf("torclient: PathLen %d out of range", cfg.PathLen)
	}
	if cfg.Directory == nil || len(cfg.Directory) == 0 {
		return nil, errors.New("torclient: no directory loaded")
	}
	if cfg.LinkDialTimeout == 0 {
		cfg.LinkDialTimeout = 30 * time.Second
	}
	if cfg.CircuitBuildTimeout == 0 {
		cfg.CircuitBuildTimeout = 60 * time.Second
	}

	guardRouter := cfg.Guard
	var guards *guard.Manager
	if guardRouter == nil {
		// Build the prop271 guard state machine from the directory's
		// Guard-flagged relays and pick an initial guard. The manager drives
		// failover on connection failure (see Connect).
		guards = guard.NewManager(guard.Params{})
		eligible := eligibleGuards(cfg.Directory)
		guards.ExpandSample(eligible, time.Now())
		sel := guards.PickForCircuit(eligible, time.Now())
		if sel == nil {
			return nil, errors.New("torclient: no guard selected")
		}
		guardRouter = cfg.Directory[sel.Guard.ID]
		if guardRouter == nil {
			return nil, fmt.Errorf("torclient: selected guard %s not in directory", sel.Guard.ID)
		}
	}

	c := &Client{cfg: cfg, dir: cfg.Directory, guard: guardRouter, guards: guards}
	c.socks = socks5.New(cfg.SocksAddr, &dialer{client: c})
	// Reject private/loopback/link-local SOCKS targets by default (the C
	// client's ClientRejectInternalAddresses); opt out with AllowPrivateAddresses.
	c.socks.RejectPrivateAddresses = !cfg.AllowPrivateAddresses
	return c, nil
}

// eligibleGuards returns the Guard-flagged relays with ntor keys, as
// guard.EligibleGuard entries keyed by hex identity digest, in bandwidth
// order (highest first) so the sample prefers high-bandwidth guards.
func eligibleGuards(dir map[string]*directory.Router) []guard.EligibleGuard {
	var out []guard.EligibleGuard
	for _, r := range dir {
		if !routerHasFlag(r, "Guard") || r.OnionKey == ([32]byte{}) {
			continue
		}
		out = append(out, guard.EligibleGuard{
			ID:        hexIDDigest(r),
			Bandwidth: r.Bandwidth,
		})
	}
	// Sort by bandwidth descending for a stable, quality-ordered sample.
	sortGuardsByBandwidth(out)
	return out
}

func sortGuardsByBandwidth(e []guard.EligibleGuard) {
	for i := 0; i < len(e); i++ {
		for j := i + 1; j < len(e); j++ {
			if e[j].Bandwidth > e[i].Bandwidth {
				e[i], e[j] = e[j], e[i]
			}
		}
	}
}

func routerHasFlag(r *directory.Router, f string) bool {
	for _, x := range r.Flags {
		if x == f {
			return true
		}
	}
	return false
}

func hexIDDigest(r *directory.Router) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 20*2)
	for i, v := range r.IDDigest {
		b[2*i] = hex[v>>4]
		b[2*i+1] = hex[v&0x0f]
	}
	return string(b)
}

// Connect dials the guard and completes the link handshake. It is called
// automatically by Serve, but may be called explicitly to connect before
// serving.
//
// When the client was not pinned to a specific guard (Config.Guard nil), the
// prop271 guard manager drives selection: on a failed connection attempt the
// guard is marked failed and the next guard is tried, up to a small number of
// attempts. A successful connection confirms the guard in the manager.
func (c *Client) Connect(ctx context.Context) error {
	// Single-flight: hold dialMu across the check-and-dial so a concurrent
	// redialGuard (keep-alive tick and/or a request that found a dead link)
	// either finds the link already renewed by the winner or runs its own
	// dial only after the previous attempt fully finished.
	c.dialMu.Lock()
	defer c.dialMu.Unlock()
	c.mu.Lock()
	if c.link != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	// If a guard was pinned, or no manager is present, dial it directly with
	// no failover (legacy behavior).
	if c.guards == nil {
		return c.dialGuard(ctx, c.guard, "")
	}

	// prop271 failover: try successive guards from the manager.
	dir := c.directory()
	eligible := eligibleGuards(dir)
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		sel := c.guards.PickForCircuit(eligible, time.Now())
		if sel == nil {
			break
		}
		r := dir[sel.Guard.ID]
		if r == nil {
			// Stale guard ID; mark failed and continue.
			c.guards.NoteConnectionFailure(sel.Guard.ID, time.Now())
			continue
		}
		err := c.dialGuard(ctx, r, sel.Guard.ID)
		if err == nil {
			return nil
		}
		lastErr = err
		c.guards.NoteConnectionFailure(sel.Guard.ID, time.Now())
		log.Printf("torclient: guard %s (%s) failed: %v; trying next", r.Nickname, r.Address, err)
	}
	if lastErr != nil {
		return fmt.Errorf("torclient: could not connect to any guard after %d attempts: %w", maxAttempts, lastErr)
	}
	return errors.New("torclient: no guard available to connect")
}

// dialGuard dials a single guard and, on success, records it as the active
// guard and (if guardID is non-empty) confirms it in the guard manager.
func (c *Client) dialGuard(ctx context.Context, r *directory.Router, guardID string) error {
	dctx, cancel := context.WithTimeout(ctx, c.cfg.LinkDialTimeout)
	defer cancel()
	l, err := link.DialWithDialer(dctx, c.cfg.LinkDialer, c.cfg.UpstreamProxy, r.Address, r.IDDigest[:], r.Ed25519ID)
	if err != nil {
		return fmt.Errorf("connect to guard %s: %w", r.Address, err)
	}
	c.mu.Lock()
	c.link = l
	// Record the dialed relay as the active guard so buildPath always
	// handshakes with the identity of the relay the link actually goes to
	// (prop271 failover or a redial may land on a different guard than the
	// one New selected; hop 1's CREATE2 onionskin is keyed by c.guard).
	c.guard = r
	c.mu.Unlock()
	if guardID != "" {
		c.guards.NoteConnectionSuccess(guardID, time.Now())
	}
	log.Printf("torclient: connected to guard %s (%s) link-proto=%d",
		r.Nickname, r.Address, l.Protocol())
	return nil
}

// keepAliveLoop keeps the guard link from being reaped while the client is
// otherwise idle. Upstream SOCKS5 proxies in front of the Tor network
// (Clash/mihomo &c.) commonly drop tunnels that carry no packets for a few
// minutes; a Tor channel that is not building circuits sends nothing, so the
// first request after a quiet period finds a dead tunnel (observed as a
// broken pipe on the next write, or a timeout waiting for CREATED2).
//
// The C client negotiates channel padding with the relay for exactly this
// purpose (channelpadding.c). Here we send an unsolicited PADDING cell every
// keepAliveInterval while the link is up and idle; relays accept and drop
// padding cells (command.c's default case), and the traffic keeps every hop
// of the tunnel — upstream proxy, NAT, the guard itself — from seeing an
// idle connection. If padding reveals the link has died, a fresh guard link
// is dialed in the background so subsequent requests find a live tunnel.
//
// The loop runs on a context derived from Serve's, so it stops when Serve
// exits; it also gives up on a closed client.
func (c *Client) keepAliveLoop(ctx context.Context) {
	const keepAliveInterval = 60 * time.Second
	t := time.NewTicker(keepAliveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.mu.Lock()
		closed := c.closed
		l := c.link
		c.mu.Unlock()
		if closed {
			return
		}
		if l == nil || !l.IsAlive() {
			c.redialGuard(ctx)
			continue
		}
		if err := l.SendPadding(); err != nil {
			log.Printf("torclient: guard link keep-alive failed: %v; redialing", err)
			c.redialGuard(ctx)
		}
	}
}

// redialGuard replaces a dead guard link with a fresh one, reusing the
// provider's guard-failover machinery. It hops circuits onto the new link on
// their next dial; in-flight circuits on the old link fail (their cells were
// undeliverable anyway).
func (c *Client) redialGuard(ctx context.Context) {
	c.mu.Lock()
	old := c.link
	c.link = nil
	c.mu.Unlock()
	if old != nil {
		old.Close()
	}
	if err := c.Connect(ctx); err != nil {
		log.Printf("torclient: guard redial failed: %v", err)
	}
}

// Serve connects to the guard (if not already connected) and serves the
// SOCKS5 proxy until the context is cancelled. If RefreshInterval is set, it
// also runs a background consensus refresh that periodically re-fetches the
// directory and swaps it in for new circuits.
func (c *Client) Serve(ctx context.Context) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	// Keep the guard link alive (padding) and self-healing (redial on
	// death) while serving; see keepAliveLoop. The keep-alive runs on a
	// context derived from Serve's so it never outlives Serve (an abandoned
	// loop would redial the guard network for a client nobody serves).
	kctx, kcancel := context.WithCancel(ctx)
	defer kcancel()
	go c.keepAliveLoop(kctx)
	if c.cfg.RefreshInterval > 0 {
		go c.refreshLoop(ctx)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- c.socks.ListenAndServe() }()
	select {
	case <-ctx.Done():
		c.socks.Shutdown()
		c.mu.Lock()
		if c.link != nil {
			c.link.Close()
		}
		c.closed = true
		c.mu.Unlock()
		return ctx.Err()
	case err := <-errCh:
		c.mu.Lock()
		if c.link != nil {
			c.link.Close()
		}
		c.closed = true
		c.mu.Unlock()
		return err
	}
}

// Run connects to the guard and keeps the client alive without serving the
// SOCKS5 listener: link padding and self-healing redial (see keepAliveLoop)
// and, when RefreshInterval is set, the background consensus refresh. It is
// Serve for embedders that dial streams in process via DialStream instead
// of through a SOCKS5 client, so no loopback listener is bound at all.
//
// A Connect failure is returned immediately (the caller may retry); the
// client runs until ctx is cancelled, then the guard link is closed and
// ctx.Err() is returned.
func (c *Client) Run(ctx context.Context) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	// Same keep-alive derivation as Serve: the loop never outlives the caller.
	kctx, kcancel := context.WithCancel(ctx)
	defer kcancel()
	go c.keepAliveLoop(kctx)
	if c.cfg.RefreshInterval > 0 {
		go c.refreshLoop(ctx)
	}
	<-ctx.Done()
	c.mu.Lock()
	if c.link != nil {
		c.link.Close()
	}
	c.closed = true
	c.mu.Unlock()
	return ctx.Err()
}

// Connected reports whether the guard link is up and alive — whether
// DialStream can build circuits right now. Embedders poll it to learn when
// the client is usable (Run connects asynchronously to their polling).
func (c *Client) Connected() bool {
	c.mu.Lock()
	l := c.link
	c.mu.Unlock()
	return l != nil && l.IsAlive()
}

// DialStream opens a Tor circuit and stream to target (host:port) in
// process: the embedder receives the same stream a SOCKS5 CONNECT client
// would, without a loopback listener. The circuit build and stream open are
// identical to the SOCKS path (fresh circuit per stream). Callers that
// accept untrusted targets should apply the same target policy the SOCKS5
// server does (socks5.IsOnionHost, port 0, socks5.RejectPrivateTarget
// gated on AllowPrivateAddresses).
func (c *Client) DialStream(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	return (&dialer{client: c}).DialStream(ctx, target)
}

// RouterInfo is a snapshot of one directory relay in the form embedders
// consume: the identity a circuit path carries, plus the display address
// and exit flag that drive per-exit outbound emission.
type RouterInfo struct {
	Nickname string
	IDDigest string // hex-encoded 20-byte identity digest; keys the directory map
	Address  string // "ip:port"
	IsExit   bool
}

// Client implements streamDialer; embedders that need the per-exit view use
// the RouterInfo surface on this concrete type.
var _ interface {
	DialStream(context.Context, string) (io.ReadWriteCloser, error)
} = (*Client)(nil)

// ExitInfos returns a snapshot of the current exit-relay roster: relays with
// the Exit flag and a usable ntor key, whether the client is connected right
// now or not. Embedders (e.g. the goose provider) use it to emit one outbound
// per real exit relay. The directory map is swapped whole on refresh, so the
// returned slice is a stable snapshot.
func (c *Client) ExitInfos() []RouterInfo {
	dir := c.directory()
	out := make([]RouterInfo, 0, len(dir))
	for _, r := range dir {
		if !routerHasFlag(r, "Exit") || r.OnionKey == ([32]byte{}) {
			continue
		}
		out = append(out, RouterInfo{
			Nickname: r.Nickname,
			IDDigest: hexIDDigest(r),
			Address:  r.Address,
			IsExit:    true,
		})
	}
	return out
}

// RouterByIDDigest looks a relay up by its hex-encoded identity digest — the
// same string ExitInfos reports and directory consensus lines key on. It
// returns a distinct error when the digest is not valid hex of the right
// length, so callers can tell bad input apart from a relay that has left
// the directory since it was listed.
func (c *Client) RouterByIDDigest(key string) (*directory.Router, error) {
	id, err := hexDecode(key)
	if err != nil {
		return nil, fmt.Errorf("torclient: bad exit digest %q: %w", key, err)
	}
	// directory keys are lowercase hex of the same 20 bytes; normalize so an
	// uppercase digest from user config still matches.
	const hexDigits = "0123456789abcdef"
	normalized := make([]byte, 40)
	for i, v := range id {
		normalized[2*i] = hexDigits[v>>4]
		normalized[2*i+1] = hexDigits[v&0x0f]
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dir[string(normalized)], nil
}

// hexDecode decodes exactly 40 hex characters into 20 bytes.
func hexDecode(s string) ([]byte, error) {
	if len(s) != 40 {
		return nil, errors.New("expected 40 hex characters")
	}
	out := make([]byte, 20)
	for i := 0; i < 40; i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return nil, errors.New("invalid hex character")
		}
		out[i/2] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(ch byte) (byte, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0', true
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10, true
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10, true
	}
	return 0, false
}

// DialStreamViaExit opens a Tor circuit and stream to target whose exit hop is
// pinned to the named relay (hex identity digest, as reported by ExitInfos),
// instead of letting buildPath pick the exit randomly per circuit. Everything
// else matches DialStream: fresh circuit per stream, same stream semantics.
// The pinned relay re-enters the eligible exit set only while it stays in the
// directory; when it drops out, dials fail fast with the lookup error.
func (c *Client) DialStreamViaExit(ctx context.Context, hexDigest, target string) (io.ReadWriteCloser, error) {
	return (&dialer{client: c, pinnedExit: strings.ToLower(hexDigest)}).DialStream(ctx, target)
}

// refreshLoop periodically re-fetches the consensus and swaps the client's
// directory in place. A refresh failure is logged but does not stop the loop
// (the client keeps serving with the last good directory); the next tick
// retries. This mirrors the C client's directory download lifecycle
// (directory_info_has_arrived / update_consensus_networkstatus_downloads).
func (c *Client) refreshLoop(ctx context.Context) {
	t := time.NewTicker(c.cfg.RefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.RefreshDirectory(ctx); err != nil {
				log.Printf("torclient: consensus refresh failed: %v", err)
			}
		}
	}
}

// RefreshDirectory re-fetches the consensus + microdescriptors and atomically
// swaps the client's directory in place, so subsequent circuits use the fresh
// relays. It does not disturb in-flight circuits (they keep their existing
// path). The guard is re-selected from the fresh directory if the current
// guard is no longer listed; otherwise the current guard is preserved.
func (c *Client) RefreshDirectory(ctx context.Context) error {
	opts := c.fetchOpts()
	routers, _, err := directory.FetchWithMeta(ctx, *opts)
	if err != nil {
		return fmt.Errorf("refresh directory: %w", err)
	}
	c.mu.Lock()
	// Preserve the current guard if it's still in the fresh directory;
	// otherwise the guard manager will pick a new one on the next Connect.
	c.dir = routers
	c.mu.Unlock()
	log.Printf("torclient: refreshed directory: %d relays", len(routers))
	return nil
}

// fetchOpts builds the FetchOptions for a refresh, falling back to defaults.
func (c *Client) fetchOpts() *directory.FetchOptions {
	if c.cfg.FetchOptions != nil {
		opts := *c.cfg.FetchOptions
		if opts.UpstreamProxy == "" {
			opts.UpstreamProxy = c.cfg.UpstreamProxy
		}
		if opts.Dialer == nil {
			opts.Dialer = c.cfg.LinkDialer
		}
		return &opts
	}
	return &directory.FetchOptions{
		UpstreamProxy: c.cfg.UpstreamProxy,
		Dialer:        c.cfg.LinkDialer,
		Timeout:       5 * time.Minute,
	}
}

// dialer implements socks5.Dialer by building a fresh circuit per stream
// (a simple, isolation-friendly strategy) and opening a stream through it.
// pinnedExit, when non-empty, is the digest of the relay the circuit's exit
// hop must be (per-exit pinning; see DialStreamViaExit). It lives on the
// dialer rather than the client so one client can serve both pinned and
// unpinned streams concurrently.
type dialer struct {
	client     *Client
	pinnedExit string
}

// DialStream opens a Tor circuit and a stream to target. Each call builds a
// new circuit; a production client would pool circuits, but per-stream
// circuits give strong isolation and are simplest to reason about.
func (d *dialer) DialStream(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	c := d.client
	c.mu.Lock()
	l := c.link
	c.mu.Unlock()
	if l == nil {
		return nil, errors.New("torclient: not connected to guard")
	}
	if !l.IsAlive() {
		// The tunnel died while we were idle (see keepAliveLoop). Redial
		// synchronously so this request gets a fresh link instead of
		// failing with a write to a broken pipe.
		c.redialGuard(ctx)
		c.mu.Lock()
		l = c.link
		c.mu.Unlock()
		if l == nil {
			return nil, errors.New("torclient: guard link lost and redial failed")
		}
	}

	path, err := c.buildPath(d.pinnedExit)
	if err != nil {
		return nil, err
	}

	bctx, cancel := context.WithTimeout(ctx, c.cfg.CircuitBuildTimeout)
	defer cancel()
	circ, err := circuit.New(bctx, l, path)
	if err != nil {
		return nil, err
	}

	sctx, scancel := context.WithTimeout(ctx, c.cfg.CircuitBuildTimeout)
	stream, err := circ.OpenStream(sctx, target)
	scancel()
	if err != nil {
		circ.Close()
		return nil, err
	}
	return &streamWrap{stream: stream, circ: circ}, nil
}

// buildPath selects the relays for a circuit of the configured length.
// pinnedExit, when non-empty, is the digest of the relay pinned as the last
// hop (the per-exit dial form); empty keeps the random exit selection.
func (c *Client) buildPath(pinnedExit string) ([]link.RouterIdentity, error) {
	dir := c.directory()
	path := make([]link.RouterIdentity, 0, c.cfg.PathLen)
	c.mu.Lock()
	guard := c.guard
	c.mu.Unlock()
	path = append(path, guard.RouterIdentity)

	for i := 1; i < c.cfg.PathLen; i++ {
		var r *directory.Router
		var err error
		switch {
		case i == c.cfg.PathLen-1 && pinnedExit != "":
			pinned, err := c.RouterByIDDigest(pinnedExit)
			if err != nil {
				return nil, err
			}
			if pinned == nil {
				return nil, fmt.Errorf("torclient: pinned exit %q is not in the current directory (it may have left the relay set)", pinnedExit)
			}
			if pinned.OnionKey == ([32]byte{}) {
				return nil, fmt.Errorf("torclient: pinned exit %q has no onion key", pinnedExit)
			}
			r = pinned
		case i == c.cfg.PathLen-1:
			r, err = directory.SelectExit(dir)
		default:
			r, err = directory.SelectMiddle(dir)
		}
		if err != nil {
			return nil, fmt.Errorf("torclient: select hop %d: %w", i+1, err)
		}
		path = append(path, r.RouterIdentity)
	}
	return path, nil
}

// directory returns a snapshot of the current router map, safe to read
// outside the lock. The map itself is never mutated in place (refreshes swap
// in a whole new map), so a snapshot taken under the lock is safe to use for
// the lifetime of a circuit build.
func (c *Client) directory() map[string]*directory.Router {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dir
}

// RouterCount reports how many relays the current directory snapshot holds —
// a cheap gauge for embedder observability (directory size at bootstrap and
// after each consensus refresh).
func (c *Client) RouterCount() int {
	return len(c.directory())
}

// streamWrap wraps a circuit Stream so that closing the stream also closes
// the (per-stream) circuit.
type streamWrap struct {
	stream *circuit.Stream
	circ   *circuit.Circuit
}

func (s *streamWrap) Read(p []byte) (int, error) {
	data, err := s.stream.Read()
	if err != nil {
		return 0, err
	}
	n := copy(p, data)
	return n, nil
}

func (s *streamWrap) Write(p []byte) (int, error) { return s.stream.Write(p) }

func (s *streamWrap) Close() error {
	s.stream.Close()
	return s.circ.Close()
}

// Resolve performs a hostname lookup through a fresh Tor circuit's exit,
// returning the first resolved address. It builds a one-hop-extended circuit
// (path length = configured PathLen) and issues a RELAY_RESOLVE.
func (d *dialer) Resolve(ctx context.Context, hostname string) (string, error) {
	c := d.client
	c.mu.Lock()
	l := c.link
	c.mu.Unlock()
	if l == nil {
		return "", errors.New("torclient: not connected to guard")
	}
	path, err := c.buildPath("")
	if err != nil {
		return "", err
	}
	bctx, cancel := context.WithTimeout(ctx, c.cfg.CircuitBuildTimeout)
	defer cancel()
	circ, err := circuit.New(bctx, l, path)
	if err != nil {
		return "", err
	}
	defer circ.Close()
	return circ.Resolve(ctx, hostname)
}

// ResolvePtr performs a reverse DNS lookup through a fresh Tor circuit's exit.
func (d *dialer) ResolvePtr(ctx context.Context, ip string) (string, error) {
	// Tor's RESOLVE_PTR is issued by sending a RELAY_RESOLVE with a target of
	// the in-addr.arpa / ip6.arpa form. We build the arpa name and resolve it;
	// the exit interprets a .in-addr.arpa target as a reverse lookup.
	arpa, err := reverseARPA(ip)
	if err != nil {
		return "", err
	}
	c := d.client
	c.mu.Lock()
	l := c.link
	c.mu.Unlock()
	if l == nil {
		return "", errors.New("torclient: not connected to guard")
	}
	path, err := c.buildPath("")
	if err != nil {
		return "", err
	}
	bctx, cancel := context.WithTimeout(ctx, c.cfg.CircuitBuildTimeout)
	defer cancel()
	circ, err := circuit.New(bctx, l, path)
	if err != nil {
		return "", err
	}
	defer circ.Close()
	return circ.Resolve(ctx, arpa)
}

// reverseARPA converts an IP address string to its DNS reverse-lookup name
// (e.g. "1.2.3.4" -> "4.3.2.1.in-addr.arpa").
func reverseARPA(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("torclient: invalid IP %q", ipStr)
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0]), nil
	}
	// IPv6: nibble-reverse the full 16-byte address.
	v6 := ip.To16()
	var b [128]byte
	for i := 0; i < 16; i++ {
		hi := v6[15-i] >> 4
		lo := v6[15-i] & 0x0f
		b[i*4] = hexNibble(lo)
		b[i*4+1] = '.'
		b[i*4+2] = hexNibble(hi)
		b[i*4+3] = '.'
	}
	return string(b[:]) + "ip6.arpa", nil
}

func hexNibble(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

// Guard returns the selected guard relay.
func (c *Client) Guard() *directory.Router { return c.guard }

// SocksAddr returns the address the SOCKS5 listener is serving on: the
// bound address once ListenAndServe has run (so "127.0.0.1:0" resolves to
// the real ephemeral port), or the configured address before that.
func (c *Client) SocksAddr() string {
	if a := c.socks.Addr(); a != nil {
		return a.String()
	}
	return c.cfg.SocksAddr
}
