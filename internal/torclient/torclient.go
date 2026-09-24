// Package torclient is the top-level Tor client. It owns the directory, the
// guard link, a pool of circuits, and the SOCKS5 listener. Applications
// configure it with a SOCKS5 proxy address (default 127.0.0.1:7890) and
// route traffic through it.
//
// Lifecycle:
//
//	cfg := &torclient.Config{SocksAddr: "127.0.0.1:7890", PathLen: 3}
//	cli, err := torclient.New(ctx, cfg)
//	...
//	cli.Serve(ctx)   // blocks, serving SOCKS5
package torclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/proxy/tor-go/internal/circuit"
	"github.com/proxy/tor-go/internal/directory"
	"github.com/proxy/tor-go/internal/guard"
	"github.com/proxy/tor-go/internal/link"
	"github.com/proxy/tor-go/internal/socks5"
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
	// LinkDialTimeout is the timeout for connecting to the guard.
	LinkDialTimeout time.Duration
	// CircuitBuildTimeout is the timeout for building a circuit.
	CircuitBuildTimeout time.Duration
}

// Client is a running Tor client.
type Client struct {
	cfg    *Config
	mu     sync.Mutex
	link   *link.Link
	dir    map[string]*directory.Router
	guard  *directory.Router
	// guards is the prop271 guard-selection state machine. It is nil when the
	// caller pinned a specific guard via Config.Guard (no failover).
	guards *guard.Manager
	socks  *socks5.Server
	closed bool
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
	eligible := eligibleGuards(c.dir)
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		sel := c.guards.PickForCircuit(eligible, time.Now())
		if sel == nil {
			break
		}
		r := c.dir[sel.Guard.ID]
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
	l, err := link.DialWithUpstream(dctx, c.cfg.UpstreamProxy, r.Address, r.IDDigest[:])
	if err != nil {
		return fmt.Errorf("connect to guard %s: %w", r.Address, err)
	}
	c.mu.Lock()
	c.link = l
	c.guard = r
	c.mu.Unlock()
	if guardID != "" {
		c.guards.NoteConnectionSuccess(guardID, time.Now())
	}
	log.Printf("torclient: connected to guard %s (%s) link-proto=%d",
		r.Nickname, r.Address, l.Protocol())
	return nil
}

// Serve connects to the guard (if not already connected) and serves the
// SOCKS5 proxy until the context is cancelled.
func (c *Client) Serve(ctx context.Context) error {
	if err := c.Connect(ctx); err != nil {
		return err
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

// dialer implements socks5.Dialer by building a fresh circuit per stream
// (a simple, isolation-friendly strategy) and opening a stream through it.
type dialer struct {
	client *Client
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

	path, err := c.buildPath()
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
func (c *Client) buildPath() ([]link.RouterIdentity, error) {
	path := make([]link.RouterIdentity, 0, c.cfg.PathLen)
	path = append(path, c.guard.RouterIdentity)

	for i := 1; i < c.cfg.PathLen; i++ {
		var r *directory.Router
		var err error
		if i == c.cfg.PathLen-1 {
			r, err = directory.SelectExit(c.dir)
		} else {
			r, err = directory.SelectMiddle(c.dir)
		}
		if err != nil {
			return nil, fmt.Errorf("torclient: select hop %d: %w", i+1, err)
		}
		path = append(path, r.RouterIdentity)
	}
	return path, nil
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
	path, err := c.buildPath()
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
	path, err := c.buildPath()
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

// SocksAddr returns the configured SOCKS5 listen address.
func (c *Client) SocksAddr() string { return c.cfg.SocksAddr }
