# tor — goose provider plugin

This package is the [goose](https://github.com/goose-network/goose) proxy-pool
engine's **tor provider plugin**: it embeds tor-go — a from-scratch Go Tor
client — as a library and exposes it to goose as a dynamic source of outbounds
(the same shape as the Psiphon provider embedding tunnel-core). As soon as the
directory is fetched, the provider advertises one `tor`-protocol outbound per
Exit-flagged relay — independent of the guard link, like psiphon's server list —
and adds the general outbound once the client connects to its guard. A dial
through an outbound opens a Tor circuit **in process** — the outbound calls the
client's `DialStream` directly — so no SOCKS/HTTP hop exists between goose and
the Tor client:

```
goose inbound ──▶ pool ──▶ "tor" outbound ──▶ DialStream (in process, no listener)
                                                                    │
                                             embedded tor-go client: directory fetch,
                                             guard link (TLS + link v3), ntor circuits
                                             (guard → middle → exit)
                                                                    │
                                                        Tor network ──▶ internet
```

The package lives inside the tor-go module (not a separate repo) because it
embeds tor-go's `internal/` packages (`internal/torclient`,
`internal/directory`), which Go's internal-package rule confines to this
module. On the goose side it imports only
[`goose-plugin-api`](https://github.com/goose-network/goose-plugin-api) —
never goose itself — so the plugin import boundary stays acyclic.

## In-memory dials, two transport planes

The `"tor"` outbound protocol resolves the live provider (keyed by the
outbound id, at dial time) and opens a circuit+stream through it. tor-go's
connections are split into two planes that ride different dialers:

- **Control plane — the directory fetches that discover the relay roster**
  (consensus + microdescriptors from the authorities, fallback ORPorts, and
  the hourly consensus refresh). These ride the provider's `upstream_proxy`:
  when the spec names a goose route (`outbound:`/`pool:`/`chain:`), the
  injected route dialer (`goose-plugin-api`'s `UpstreamDialer`) carries them;
  otherwise the engine's stack dialer (`StackDialer`) carries the hop *to* the
  config's raw SOCKS5 `upstream_proxy` address, and the SOCKS5 tunnel to the
  authority runs on top. An injected route supersedes the raw address (the
  route already is the upstream proxy; chaining a raw SOCKS5 hop inside it
  would double-proxy), so the address is dropped when a route is injected.
- **Data path — the guard link every circuit rides** (and thus every
  outbound's relay traffic). By default this rides the engine's stack dialer
  (`StackDialer` — goose's layer-3/4 stack, system kernel or gvisor netstack),
  or direct when none is injected, and **never** the provider
  `upstream_proxy` (the fetch-only contract). The opt-in
  `"link_via_upstream": true` config key, combined with a spec-level
  `upstream_proxy` naming a goose route, additionally carries the guard link
  through that same injected route dialer — which returns a completed
  tunnel, so the guard TLS + v3 link handshake layer over it unchanged. This
  is the openrung -> tor data path for hosts where direct guard dials are
  blocked. The route must not contain the tor outbound itself (data-path
  cycle). The separate outbound-level `upstream_proxy` (resolved by the
  router) still routes an individual outbound's server connection; the tor
  outbound has no server dial of its own.

Target policy matches the SOCKS5 server's (which mirrors the C client's
`connection_edge.c`): `.onion` targets are refused (no hidden-service
subsystem), port 0 is refused, and private/loopback/link-local targets are
refused unless `allow_private_addresses` is set.

## How goose consumes this

tor-go is published as the versioned module
`github.com/goose-network/tor-go`; goose requires it directly from the module
proxy (no local `replace`) and triggers registration with a blank import in
its `include/register.go`:

```go
import _ "github.com/goose-network/tor-go/plugins/tor"
```

## Bootstrap lifecycle

A Tor client must fetch a signed microconsensus + microdescriptors, select a
guard, and complete a TLS link handshake before it can serve a single byte —
easily a minute on first run. The provider therefore starts tor-go in a
background goroutine from the factory:

- `Outbounds()` advertises **one outbound per Exit-flagged relay** as soon as
  the directory is fetched — independent of guard-link readiness, the tor
  analogue of psiphon's datastore server list — and adds the general `tor`
  outbound once the client connects to its guard. Per-exit ids are
  `<outbound_id>-<nickname>-<digest-prefix>-<ip:port>`, so the id itself shows
  the relay's OR address; the general outbound keeps the plain `<outbound_id>`
  (it rides a live circuit, no single server). Each change signals `Watch()`
  so the engine repolls promptly instead of waiting for the 2-minute fallback
  poll.
- A failed bootstrap (upstream down, authorities unreachable, no relays with
  onion keys) is retried with exponential backoff capped at 60s in the same
  goroutine — a temporarily dead network does not kill the provider; the last
  fetched roster stays advertised meanwhile.
- The whole client lifetime is tied to the provider's context: cancelling it
  stops the guard link, the consensus refresh, and the idle-tunnel keep-alive
  loop (`Client.Run`; no listener is ever bound).
- While connected, the consensus is re-fetched **hourly** (a microconsensus
  is valid ~3h) so descriptor churn does not eventually break every circuit
  build while the outbound stays advertised.

## Config

The provider config is a JSON object whose keys map onto `torclient.Config`
and `directory.FetchOptions` where they make sense as provider knobs:

```json
{
  "upstream_proxy": "127.0.0.1:7890",
  "link_via_upstream": false,
  "path_len": 3,
  "outbound_id": "tor",
  "fetch_timeout_seconds": 300,
  "max_microdescs": 400,
  "verify_signatures": true,
  "use_fallbacks": false,
  "link_dial_timeout_seconds": 45,
  "link_idle_timeout_seconds": 0,
  "circuit_build_timeout_seconds": 90,
  "allow_private_addresses": false
}
```

| Key | Default | Meaning |
|---|---|---|
| `upstream_proxy` | `""` (direct) | SOCKS5 proxy tor-go dials *through* to reach the **directory authorities only** (roster discovery, e.g. a local Clash/V2Ray instance). The hop to the proxy still goes through the engine stack. By default it never routes the guard link / relay dials — those ride the engine stack (the `link_via_upstream` opt-in below is the guard-link exception). When the spec-level `upstream_proxy` names a goose route the raw address is dropped — **unless** `link_via_upstream` is also set, in which case it is kept and the directory fetches are decoupled onto the engine stack + this address so roster discovery does not ride the same tunnel as the guard link. |
| `link_via_upstream` | `false` | Opt the **guard link** (the data path every circuit rides) into the spec-level injected upstream route too — openrung -> tor on hosts where direct guard dials are blocked. Requires a spec-level `upstream_proxy` naming a goose route (`outbound:`/`pool:`/`chain:`); no effect otherwise. The route dialer returns a completed tunnel; the guard TLS + v3 link handshake run over it unchanged. The route must not contain the tor outbound itself. |
| `path_len` | `3` | Circuit hops (guard / middle / exit). |
| `outbound_id` | `"tor"` | The id of the outbound contributed to goose's pool; the outbound dials whichever live provider registered under this id. |
| `fetch_timeout_seconds` | `300` | Timeout for the directory bootstrap (consensus + microdescriptor fetch). |
| `max_microdescs` | `0` (all) | Cap on fetched microdescriptors — the slow part of bootstrap is one GET per digest. |
| `verify_signatures` | `true` | Verify the v3 consensus signature quorum. Directory dirports serve plain HTTP, so the quorum is the only thing that authenticates the consensus — leave this on unless you know why not. |
| `use_fallbacks` | `false` | Bootstrap over a CREATE_FAST one-hop fallback circuit instead of the authorities. The fallback path is unauthenticated, so it cannot be combined with `verify_signatures`. |
| `link_dial_timeout_seconds` | `0` (client default) | Timeout for connecting to the guard. |
| `link_idle_timeout_seconds` | `0` (120s) | Rolling first-byte read deadline on the guard link. On expiry the link is redialed only under sustained unanswered outbound (≥2 real cells since the last inbound, latest write younger than half the window) — a deaf-but-unclosed upstream tunnel; a healthy idle link is kept. |
| `circuit_build_timeout_seconds` | `0` (client default) | Timeout for building a circuit. |
| `allow_private_addresses` | `false` | Permit stream targets that are private/loopback/link-local (refused by default, mirroring the C client). |

A minimal goose config using the provider:

```json
{
  "engine": { "api": { "listen": "127.0.0.1:9099" }, "db": "goose.db" },
  "inbounds": [
    { "id": "in-socks", "protocol": "socks5", "listen": "127.0.0.1:11080" }
  ],
  "providers": [
    {
      "id": "tor-prov",
      "provider": "tor",
      "pool_id": "tor-pool",
      "config": { "upstream_proxy": "127.0.0.1:7890" }
    }
  ]
}
```

(Note the port semantics: `11080` is goose's inbound; `7890` is the upstream
proxy tor-go dials through to fetch the directory. There is no tor-go listener
anymore — dials go straight from the engine to the embedded client in memory.)

## Verifying it works

With the config above (inbound at `127.0.0.1:11080`), after the provider logs
`tor-go client connected to guard` (~a minute of directory bootstrap on first
run):

```sh
curl -s -x socks5h://127.0.0.1:11080 https://check.torproject.org/api/ip
# → {"IsTor":true,"IP":"<tor exit relay>"}
```

`IsTor:true` proves the request traversed a real 3-hop Tor circuit.
