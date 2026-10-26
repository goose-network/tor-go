// outbound.go — the "tor" outbound protocol: dials streams in memory through
// a live provider's embedded tor-go client. The provider emits ONE outbound
// of this protocol (config {"tunnel": <outbound id>}); at dial time the
// outbound resolves the live provider from the registry below and calls its
// dialStream, so no SOCKS/HTTP hop exists between goose and the Tor client —
// the connection goose hands to the router IS the Tor circuit's stream.
//
// The registry is keyed by the general outbound ID (the engine enforces
// unique outbound IDs, so two tor providers must use distinct outbound_id
// values). Dial-time resolution means a restarted provider is picked up by
// the next dial without rebuilding the pool.

package tor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	pub "github.com/goose-network/goose-plugin-api"

	"github.com/goose-network/tor-go/internal/socks5"
)

// liveProviders maps a tor provider's general outbound ID to the live
// provider instance. Keyed and resolved at dial time (see above).
var liveProviders sync.Map // map[string]*Provider

func registerLiveProvider(p *Provider) {
	liveProviders.Store(p.cfg.OutboundID, p)
}

// unregisterLiveProvider removes p only if it is still the registered
// instance, so a restarted provider that already re-registered under the
// same ID is not clobbered by the old instance's Close.
func unregisterLiveProvider(p *Provider) {
	liveProviders.CompareAndDelete(p.cfg.OutboundID, p)
}

func lookupLiveProvider(id string) (*Provider, bool) {
	v, ok := liveProviders.Load(id)
	if !ok {
		return nil, false
	}
	p, ok := v.(*Provider)
	return p, ok
}

// Outbound is the "tor" protocol outbound. tunnel names the live provider
// (its outbound ID); allowPrivate mirrors the provider's
// allow_private_addresses into the dial path.
type Outbound struct {
	id           string
	tunnel       string
	allowPrivate bool
}

// New is the pub.OutboundFactory registered as "tor". The config map is the
// provider-emitted {"id", "tunnel", "allow_private"}; the engine-injected
// "_dialer" key (StackDialer) is intentionally ignored — the tor client's
// own connections already dial through the engine stack via the provider.
func New(cfg map[string]any) (pub.Outbound, error) {
	id, _ := cfg["id"].(string)
	if id == "" {
		id = "tor"
	}
	tunnel, _ := cfg["tunnel"].(string)
	if tunnel == "" {
		tunnel = id
	}
	allowPrivate, _ := cfg["allow_private"].(bool)
	return &Outbound{id: id, tunnel: tunnel, allowPrivate: allowPrivate}, nil
}

func (o *Outbound) Protocol() string { return "tor" }

func (o *Outbound) ID() string { return o.id }

// Address is empty: a Tor circuit has no single dial endpoint (the exit is
// chosen per stream), so there is nothing for the engine to probe or
// geolocate; liveness is the dial itself.
func (o *Outbound) Address() string { return "" }

func (o *Outbound) Location() *pub.Location  { return nil }
func (o *Outbound) Stats() pub.OutboundStats { return pub.OutboundStats{} }
func (o *Outbound) DialContext(ctx context.Context, network pub.Network, address string) (net.Conn, error) {
	if network != pub.NetworkTCP {
		return nil, errors.New("tor: only TCP streams are supported (Tor tunnels TCP)")
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("tor: bad target %q: %w", address, err)
	}

	// Target policy, mirroring the SOCKS5 server's checks (which mirror the
	// C client's connection_edge.c): .onion needs the hidden-service
	// subsystem this client does not implement; port 0 is refused; private
	// targets are refused unless explicitly allowed.
	if socks5.IsOnionHost(host) {
		return nil, fmt.Errorf("tor: refusing .onion target %q (hidden services unsupported)", address)
	}
	if portStr == "0" {
		return nil, errors.New("tor: refusing connection to port 0")
	}
	if !o.allowPrivate && socks5.RejectPrivateTarget(host) {
		return nil, fmt.Errorf("tor: refusing private/local target %q", address)
	}

	p, ok := lookupLiveProvider(o.tunnel)
	if !ok {
		return nil, fmt.Errorf("tor: no live provider for tunnel %q (is the tor provider running?)", o.tunnel)
	}
	return p.dialStream(ctx, address)
}

func init() {
	pub.Register("tor", New)
}

// streamConn adapts the client's io.ReadWriteCloser stream to net.Conn. The
// Tor stream is a relay-level stream: there is no local/remote socket
// address, and deadlines are not implemented by the underlying circuit
// stream, so they are no-ops (the engine sets deadlines only on inbound
// client connections, never on outbound dial results).
type streamConn struct {
	io.ReadWriteCloser
}

type torAddr struct{}

func (torAddr) Network() string { return "tor" }
func (torAddr) String() string  { return "tor-circuit" }

func (c streamConn) LocalAddr() net.Addr  { return torAddr{} }
func (c streamConn) RemoteAddr() net.Addr { return torAddr{} }

func (c streamConn) SetDeadline(t time.Time) error      { return nil }
func (c streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c streamConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = streamConn{}
