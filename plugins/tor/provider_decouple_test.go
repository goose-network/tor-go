package tor

import (
	"context"
	"net"
	"testing"

	pub "github.com/goose-network/goose-plugin-api"
)

// TestResolvePlanesFetchDecoupling verifies the fetch-decoupling seam: when
// link_via_upstream is opted in AND a raw config upstream_proxy address is also
// present, the guard link rides the injected route while the directory fetches
// are decoupled onto the engine stack + that raw SOCKS5 address. The roster-
// discovery control plane then does not ride the same upstream tunnel as the
// data path, so a deaf/slow openrung tunnel cannot stall the consensus fetch.
// The raw address is preserved (it feeds FetchOptions only; the link plane's
// Config.UpstreamProxy stays empty).
func TestResolvePlanesFetchDecoupling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stackRec, routeRec := &dialRecorder{}, &dialRecorder{}
	cfg := map[string]any{
		pub.StackDialerKey:    fakeStackDialer{stackRec},
		pub.UpstreamDialerKey: fakeUpstreamDialer{routeRec},
	}
	pc := providerConfig{LinkViaUpstream: true, UpstreamProxy: "127.0.0.1:7890"}
	d, viaRoute := resolvePlanes(cfg, &pc)
	if !viaRoute {
		t.Fatal("injected route not reported")
	}
	// The raw fetch address is kept for the decoupled fetch plane.
	if pc.UpstreamProxy != "127.0.0.1:7890" {
		t.Fatalf("raw fetch upstream = %q, want preserved for decoupled fetches", pc.UpstreamProxy)
	}

	// Guard link rides the injected route (openrung -> tor).
	conn, err := d.link(ctx, "tcp", "1.2.3.4:9001")
	if err != nil {
		t.Fatalf("link dial: %v", err)
	}
	_ = conn.Close()
	if got := routeRec.recorded(); len(got) != 1 || got[0] != "tcp 1.2.3.4:9001" {
		t.Fatalf("link dialed %v, want the guard relay via the route", got)
	}
	if got := stackRec.recorded(); len(got) != 0 {
		t.Fatalf("link also rode the stack %v, want the route only", got)
	}

	// Fetch plane is decoupled onto the STACK, not the route.
	conn, err = d.fetch(ctx, "tcp", "128.31.0.39:9231")
	if err != nil {
		t.Fatalf("fetch dial: %v", err)
	}
	_ = conn.Close()
	if got := stackRec.recorded(); len(got) != 1 || got[0] != "tcp 128.31.0.39:9231" {
		t.Fatalf("fetch dialed %v, want the authority via the decoupled stack dialer", got)
	}
	if got := routeRec.recorded(); len(got) != 1 {
		t.Fatalf("fetch rode the route %v, want it decoupled (route used by the link only)", got)
	}
}

// TestResolvePlanesCoupledWithoutRawAddress verifies that link_via_upstream
// WITHOUT a raw upstream_proxy address keeps the fetches coupled to the route
// (the prior behavior): both planes ride the injected route and the empty raw
// address is dropped so the fetchOpts fallback never chains a SOCKS5 hop.
func TestResolvePlanesCoupledWithoutRawAddress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stackRec, routeRec := &dialRecorder{}, &dialRecorder{}
	cfg := map[string]any{
		pub.StackDialerKey:    fakeStackDialer{stackRec},
		pub.UpstreamDialerKey: fakeUpstreamDialer{routeRec},
	}
	pc := providerConfig{LinkViaUpstream: true}
	d, viaRoute := resolvePlanes(cfg, &pc)
	if !viaRoute {
		t.Fatal("injected route not reported")
	}
	if pc.UpstreamProxy != "" {
		t.Fatalf("raw fetch upstream = %q, want empty (coupled to route)", pc.UpstreamProxy)
	}
	if _, err := d.link(ctx, "tcp", "1.2.3.4:9001"); err != nil {
		t.Fatalf("link dial: %v", err)
	}
	if _, err := d.fetch(ctx, "tcp", "128.31.0.39:9231"); err != nil {
		t.Fatalf("fetch dial: %v", err)
	}
	// Both planes rode the route; the stack was never used.
	if got := routeRec.recorded(); len(got) != 2 {
		t.Fatalf("route dialed %v, want both link and fetch coupled to it", got)
	}
	if got := stackRec.recorded(); len(got) != 0 {
		t.Fatalf("stack dialed %v, want none (both planes on the route)", got)
	}
}

// TestResolvePlanesDecoupledRouteOnlyFetchNotNil is the regression for the
// route-only re-coupling bug. When an upstream ROUTE dialer is injected but NO
// engine stack dialer (route-only embedding), link_via_upstream + a raw fetch
// address takes the decoupled branch with no stack to ride. Before the fix
// d.fetch was left nil, and torclient.fetchOpts falls back to cfg.LinkDialer
// (the ROUTE) for a nil Dialer — re-coupling the hourly consensus refresh to the
// upstream tunnel and chaining the raw SOCKS5 address inside it. The fix sets an
// explicit system dialer so decoupled fetches stay off the route.
func TestResolvePlanesDecoupledRouteOnlyFetchNotNil(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	routeRec := &dialRecorder{}
	cfg := map[string]any{
		pub.UpstreamDialerKey: fakeUpstreamDialer{routeRec},
		// No StackDialerKey: route-only embedding.
	}
	pc := providerConfig{LinkViaUpstream: true, UpstreamProxy: "127.0.0.1:7890"}
	d, viaRoute := resolvePlanes(cfg, &pc)
	if !viaRoute {
		t.Fatal("injected route not reported")
	}
	if d.fetch == nil {
		t.Fatal("decoupled fetch dialer is nil; fetchOpts would fall back to the route (re-coupling)")
	}
	if pc.UpstreamProxy != "127.0.0.1:7890" {
		t.Fatalf("raw fetch upstream = %q, want preserved for decoupled fetches", pc.UpstreamProxy)
	}

	// The guard link rides the injected route.
	lc, err := d.link(ctx, "tcp", "1.2.3.4:9001")
	if err != nil {
		t.Fatalf("link dial: %v", err)
	}
	_ = lc.Close()
	if got := routeRec.recorded(); len(got) != 1 || got[0] != "tcp 1.2.3.4:9001" {
		t.Fatalf("link dialed %v, want the guard relay via the route", got)
	}

	// The fetch plane dials DIRECTLY (system dialer), not via the route. Dial a
	// loopback listener and confirm it connects without touching the route.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	fc, err := d.fetch(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("decoupled fetch dial: %v", err)
	}
	_ = fc.Close()
	if got := routeRec.recorded(); len(got) != 1 {
		t.Fatalf("fetch rode the route %v, want it decoupled (system dialer; route used by the link only)", got)
	}
}
