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
	"sync"
	"time"

	"github.com/proxy/tor-go/internal/circuit"
	"github.com/proxy/tor-go/internal/directory"
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

	guard := cfg.Guard
	if guard == nil {
		g, err := directory.SelectGuard(cfg.Directory)
		if err != nil {
			return nil, err
		}
		guard = g
	}

	c := &Client{cfg: cfg, dir: cfg.Directory, guard: guard}
	c.socks = socks5.New(cfg.SocksAddr, &dialer{client: c})
	return c, nil
}

// Connect dials the guard and completes the link handshake. It is called
// automatically by Serve, but may be called explicitly to connect before
// serving.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.link != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	dctx, cancel := context.WithTimeout(ctx, c.cfg.LinkDialTimeout)
	defer cancel()
	l, err := link.DialWithUpstream(dctx, c.cfg.UpstreamProxy, c.guard.Address, c.guard.IDDigest[:])
	if err != nil {
		return fmt.Errorf("torclient: connect to guard %s: %w", c.guard.Address, err)
	}
	c.mu.Lock()
	c.link = l
	c.mu.Unlock()
	log.Printf("torclient: connected to guard %s (%s) link-proto=%d",
		c.guard.Nickname, c.guard.Address, l.Protocol())
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

// Guard returns the selected guard relay.
func (c *Client) Guard() *directory.Router { return c.guard }

// SocksAddr returns the configured SOCKS5 listen address.
func (c *Client) SocksAddr() string { return c.cfg.SocksAddr }
