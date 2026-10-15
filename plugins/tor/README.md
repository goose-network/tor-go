# tor — goose provider plugin

This package is the [goose](https://github.com/goose-network/goose) proxy-pool
engine's **tor provider plugin**: it embeds tor-go — a from-scratch Go Tor
client — as a library and exposes it to goose as a dynamic source of outbounds
(the same shape as the Psiphon provider embedding tunnel-core). Once the
embedded client is serving, the provider advertises one `socks5` outbound
pointing at the client's loopback SOCKS5 listener; goose merges it into the
provider's managed pool, and every inbound routed through that pool forwards
traffic through real multi-hop Tor circuits:

```
goose inbound ──▶ pool (managed by provider) ──▶ socks5 ──▶ embedded tor-go client
                                                                      │
                                        directory fetch, guard link (TLS+link v3),
                                        ntor circuits (guard → middle → exit)
                                                                      │
                                                                Tor network ──▶ internet
```

The package lives inside the tor-go module (not a separate repo) because it
embeds tor-go's `internal/` packages (`internal/torclient`,
`internal/directory`), which Go's internal-package rule confines to this
module. On the goose side it imports only
[`goose-plugin-api`](https://github.com/goose-network/goose-plugin-api) —
never goose itself — so the plugin import boundary stays acyclic.

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

- `Outbounds()` returns an **empty set** until the SOCKS5 listener is bound,
  then signals `Watch()` so the engine repolls promptly instead of waiting
  for the 2-minute fallback poll.
- A failed bootstrap (upstream down, authorities unreachable, no relays with
  onion keys) is retried with exponential backoff capped at 60s in the same
  goroutine — a temporarily dead network does not kill the provider; the pool
  simply stays empty.
- The whole client lifetime is tied to the provider's context: cancelling it
  stops the listener, the guard link, the consensus refresh, and the
  idle-tunnel keep-alive loop.
- While serving, the consensus is re-fetched **hourly** (a microconsensus is
  valid ~3h) so descriptor churn does not eventually break every circuit
  build while the outbound stays advertised.

## Config

The provider config is a JSON object whose keys map onto `torclient.Config`
and `directory.FetchOptions` where they make sense as provider knobs:

```json
{
  "upstream_proxy": "127.0.0.1:7890",
  "path_len": 3,
  "socks_listen": "127.0.0.1:0",
  "outbound_id": "tor",
  "fetch_timeout_seconds": 300,
  "max_microdescs": 400,
  "verify_signatures": true,
  "use_fallbacks": false,
  "link_dial_timeout_seconds": 45,
  "circuit_build_timeout_seconds": 90,
  "allow_private_addresses": false
}
```

| Key | Default | Meaning |
|---|---|---|
| `upstream_proxy` | `""` (direct) | SOCKS5 proxy tor-go dials *through* to reach relays and directory authorities (e.g. a local Clash/V2Ray instance). |
| `path_len` | `3` | Circuit hops (guard / middle / exit). |
| `socks_listen` | `127.0.0.1:0` | tor-go's own SOCKS5 listener; the default binds an ephemeral loopback port. |
| `outbound_id` | `"tor"` | The id of the outbound contributed to goose's pool. |
| `fetch_timeout_seconds` | `300` | Timeout for the directory bootstrap (consensus + microdescriptor fetch). |
| `max_microdescs` | `0` (all) | Cap on fetched microdescriptors — the slow part of bootstrap is one GET per digest. |
| `verify_signatures` | `true` | Verify the v3 consensus signature quorum. Directory dirports serve plain HTTP, so the quorum is the only thing that authenticates the consensus — leave this on unless you know why not. |
| `use_fallbacks` | `false` | Bootstrap over a CREATE_FAST one-hop fallback circuit instead of the authorities. The fallback path is unauthenticated, so it cannot be combined with `verify_signatures`. |
| `link_dial_timeout_seconds` | `0` (client default) | Timeout for connecting to the guard. |
| `circuit_build_timeout_seconds` | `0` (client default) | Timeout for building a circuit. |
| `allow_private_addresses` | `false` | Permit SOCKS5 targets that are private/loopback/link-local (refused by default, mirroring the C client). |

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
proxy tor-go dials through; tor-go's own listener is loopback-internal and
ephemeral by default.)

## Verifying it works

With the config above (inbound at `127.0.0.1:11080`), after the provider
logs `tor-go SOCKS5 listener up` (~a minute of directory bootstrap on first
run):

```sh
curl -s -x socks5h://127.0.0.1:11080 https://check.torproject.org/api/ip
# → {"IsTor":true,"IP":"<tor exit relay>"}
```

`IsTor:true` proves the request traversed a real 3-hop Tor circuit.
