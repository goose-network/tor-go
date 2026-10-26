// outbound.go — the "tor" outbound protocol: dials streams in memory through
// a live provider's embedded tor-go client. The provider emits the general
// outbound (config {"tunnel": <outbound id>}, random exit per circuit) plus
// one per-relay outbound (also carrying {"exit": <hex identity digest>},
// which pins the circuit's exit hop); at dial time the outbound resolves the
// live provider from the registry below and calls its dial path, so no
// SOCKS/HTTP hop exists between goose and the Tor client — the connection
// goose hands to the router IS the Tor circuit's stream.
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
// allow_private_addresses into the dial path; exitDigest, when non-empty,
// pins the circuit's exit hop to one relay (the per-server form of the tor
// outbound — see Provider.Outbounds).
type Outbound struct {
	id           string
	tunnel       string
	allowPrivate bool
	exitDigest   string
	exitName     string
}

// New is the pub.OutboundFactory registered as "tor". The config map is the
// provider-emitted {"id", "tunnel", "allow_private"} for the general
// outbound, plus {"exit": <hex digest>, "exit_name": <nickname>} on
// per-relay outbounds; the engine-injected "_dialer" key (StackDialer) is
// intentionally ignored — the tor client's own connections already dial
// through the engine stack via the provider.
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
	exitDigest, _ := cfg["exit"].(string)
	exitName, _ := cfg["exit_name"].(string)
	return &Outbound{id: id, tunnel: tunnel, allowPrivate: allowPrivate, exitDigest: exitDigest, exitName: exitName}, nil
}

func (o *Outbound) Protocol() string { return "tor" }

func (o *Outbound) ID() string { return o.id }

// Address reports the pinned exit relay's OR address on per-relay outbounds
// (giving the engine something to show, geolocate, and probe for
// reachability); the general outbound has no single endpoint, so it stays
// empty.
func (o *Outbound) Address() string {
	if o.exitDigest == "" {
		return ""
	}
	p, ok := lookupLiveProvider(o.tunnel)
	if !ok {
		return ""
	}
	addr, err := p.exitAddress(o.exitDigest)
	if err != nil {
		return ""
	}
	return addr
}

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
	return p.dialStreamExit(ctx, o.exitDigest, address)
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
