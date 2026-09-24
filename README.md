# tor-go

A from-scratch Go reimplementation of a Tor client, modeled on the C reference
implementation (Tor 0.4.9.x) located at `../tor`. It speaks the Tor link and
circuit protocols directly, builds multi-hop circuits, and exposes a local
SOCKS5 proxy that applications route traffic through.

## Status

### What works

- **TLS link layer + v3 link handshake** — `VERSIONS -> CERTS ->
  AUTH_CHALLENGE -> NETINFO`, with relay identity verified from the CERTS cell
  (RSA + ed25519 + cross-cert) and a fallback TLS-cert SHA-1 digest check. As a
  client, tor-go receives and verifies the relay's CERTS, drains
  AUTH_CHALLENGE, and sends NETINFO; it does not send AUTHENTICATE (only the
  relay authenticates to the client).
- **Circuit handshakes** — ntor v1 (`ntor-curve25519-sha256`) and ntor v3
  (selected when the relay advertises `Relay>=4` and has an ed25519 identity),
  plus `CREATE_FAST` one-hop circuits for directory bootstrap.
- **Multi-hop circuits** — `CREATE2`/`CREATED2` for the first hop and
  `EXTEND2`/`EXTENDED2` for subsequent hops, with full link-specifier
  construction (IPv4+port, RSA digest, ed25519 identity).
- **Relay crypto** — layered AES-128-CTR + SHA-1 running-digest per hop
  (the "tor1" relay crypto), forward/backward encryption and integrity.
- **SOCKS5 proxy** — `CONNECT`, `RESOLVE`, and `RESOLVE_PTR` (Tor extensions)
  with no-auth (`0x00`) and username/password (`0x02`, RFC 1929) methods.
- **Directory parsing** — microconsensus + microdescriptor parsing into router
  identities (the `r`/`m`/`a` consensus lines and `onion-key`/`ntor-onion-key`
  microdescriptor lines).
- **Directory fetch** — over HTTPS from directory authorities (tunneled through
  the upstream proxy), or over a one-hop `CREATE_FAST` circuit to a fallback
  directory cache via `BEGIN_DIR`.
- **Consensus signature verification** — fetches authority certificates and
  verifies a quorum of v3 directory signatures on the consensus.
- **Guard state machine (proposal 271)** — bounded sample, primary/confirmed
  guards, failover on connection failure.
- **SENDME flow control** — circuit-level and stream-level windows
  (`CIRCWINDOW_START=1000`, `CIRCWINDOW_INCREMENT=100`, stream windows 500/50)
  with package-window backpressure and `RELAY_EARLY` cap (8 per circuit).
- **Private-address rejection** — SOCKS5 targets that are private, loopback, or
  link-local (and `localhost`/`*.local`) are refused, mirroring the C client's
  `ClientRejectInternalAddresses`.
- **NETINFO clock-skew detection** — warns when the peer's reported timestamp
  differs from local time by more than one hour.

### Out of scope

- Bridges and pluggable transports.
- Full hidden services beyond `.onion` refusal (the SOCKS5 layer refuses
  `.onion` targets with "command not supported").
- Link padding / circuit padding.
- Congestion control beyond the v1 SENDME windowed flow control.

## Topology

```
  curl ──► tor-go SOCKS5 (127.0.0.1:1080) ──► tor-go client
                                                      │
                                                      ▼
                                  upstream SOCKS5 (127.0.0.1:7890)
                                                      │
                                                      ▼
                                            Tor network ──► target
```

`127.0.0.1:7890` is the address of an **upstream** SOCKS5 proxy that tor-go
dials *through* to reach relays and directory authorities (e.g. a local
Clash/V2Ray instance). It is **not** tor-go's own listener — tor-go's
client-facing listener is the SOCKS5 address (`127.0.0.1:1080` by default).
Empty upstream means tor-go dials relays directly.

## Quickstart

Build the command:

```sh
go build ./cmd/tor-go
```

Bootstrap a real directory over the network (through the upstream proxy) and
serve a SOCKS5 proxy:

```sh
./tor-go -fetch-dir -upstream 127.0.0.1:7890 -socks 127.0.0.1:1080
```

Then route an application through it:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://check.torproject.org
```

File-based mode (supply your own consensus + microdescriptors, no network
fetch):

```sh
./tor-go -consensus consensus.txt -microdescriptors microdescs.txt \
    -socks 127.0.0.1:1080 -upstream 127.0.0.1:7890
```

Mock-directory mode (built-in mock relays, for testing without a real
directory):

```sh
./tor-go -mock-dir -socks 127.0.0.1:1080
```

## CLI flags

| Flag                | Description                                                        | Default            |
|---------------------|--------------------------------------------------------------------|--------------------|
| `-consensus`        | Path to a (micro)consensus file                                    | `""`               |
| `-microdescriptors` | Path to a microdescriptors file                                    | `""`               |
| `-socks`            | SOCKS5 listen address (applications connect here)                  | `127.0.0.1:1080`   |
| `-pathlen`          | Circuit path length                                                | `3`                |
| `-mock-dir`         | Use a built-in mock directory (for testing)                        | `false`            |
| `-upstream`         | SOCKS5 upstream proxy to reach relays (e.g. `127.0.0.1:7890`)      | `""`               |
| `-fetch-dir`        | Bootstrap a real directory over the network (requires `-upstream` or direct outbound) | `false` |

Exactly one directory source must be chosen: `-fetch-dir`, `-mock-dir`, or the
`-consensus` + `-microdescriptors` pair.

## Configuration as a library

`torclient.Config` is the programmatic configuration for the client. The
command in `cmd/tor-go` is a thin wrapper that builds a `Config` and calls
`Serve`.

```go
package main

import (
    "context"
    "github.com/proxy/tor-go/internal/directory"
    "github.com/proxy/tor-go/internal/torclient"
)

func main() {
    routers, err := directory.Fetch(context.Background(), directory.FetchOptions{
        UpstreamProxy:    "127.0.0.1:7890",
        VerifySignatures: true,
    })
    if err != nil { panic(err) }

    cfg := &torclient.Config{
        SocksAddr:     "127.0.0.1:1080",
        PathLen:       3,
        Directory:     routers,
        UpstreamProxy: "127.0.0.1:7890",
    }
    cli, err := torclient.New(context.Background(), cfg)
    if err != nil { panic(err) }
    cli.Serve(context.Background())
}
```

Key `Config` fields (from the struct comments in
`internal/torclient/torclient.go`):

| Field                    | Description                                                                                       |
|--------------------------|---------------------------------------------------------------------------------------------------|
| `SocksAddr`              | Address the SOCKS5 proxy listens on. Library default `127.0.0.1:7890`; the `cmd/tor-go` CLI overrides this to `127.0.0.1:1080` via its `-socks` flag. |
| `PathLen`                | Circuit path length (default 3: guard, middle, exit).                                             |
| `Guard`                  | Relay to use as the guard (first hop). If empty, one is selected from the directory.              |
| `Directory`              | Parsed directory (consensus + microdescriptors). If nil, `New` returns an error.                  |
| `UpstreamProxy`          | SOCKS5 proxy the link layer dials through to reach relays. Empty means dial directly.             |
| `LinkDialTimeout`        | Timeout for connecting to the guard.                                                              |
| `CircuitBuildTimeout`    | Timeout for building a circuit.                                                                   |
| `RefreshInterval`        | How often to re-fetch the consensus in the background while serving. Zero = no background refresh.|
| `FetchOptions`           | Configures the background consensus refresh / `RefreshDirectory`. Set `VerifySignatures` for real use. |
| `AllowPrivateAddresses`  | When false (default), refuse SOCKS5 targets that are private/loopback/link-local.                 |

## Project layout

```
tor-go/
├── cmd/tor-go/          # Standalone Tor client command (loads a directory, serves SOCKS5)
└── internal/
    ├── torclient/       # Top-level client: owns directory, guard link, circuit pool, SOCKS5 listener
    ├── socks5/          # SOCKS5 (RFC 1928) proxy server; CONNECT/RESOLVE/RESOLVE_PTR with no-auth + userpass
    ├── link/            # Tor link layer: TLS connection + v3 link handshake (VERSIONS/CERTS/NETINFO)
    ├── circuit/         # Origin circuits: CREATE2/EXTEND2, ntor, relay cells, SENDME flow control
    ├── ntor/            # ntor v1 and ntor v3 circuit-extension handshakes (Curve25519 + HKDF-SHA256)
    ├── fast/            # CREATE_FAST one-hop handshake (TAP key expansion, for directory bootstrap)
    ├── relaycrypto/     # Layered AES-128-CTR + SHA-1 relay-cell crypto per hop (tor1 relay crypto)
    ├── torcell/         # On-the-wire cell format: fixed/variable cells, relay-cell framing
    ├── directory/       # Microconsensus + microdescriptor parsing, and the directory fetcher (HTTPS / fallback circuit)
    ├── fallback/        # Hardcoded fallback directory caches (fallback_dirs.inc) and its line parser
    ├── guard/           # prop271 guard-selection state machine (sample, primary, confirmed guards)
    ├── proxy/           # Outbound dialer through an upstream SOCKS5 proxy (used by the link layer)
    └── testharness/     # In-process mock Tor relay for integration / end-to-end tests
```

## Testing

Run the full test suite:

```sh
go test ./...
```

The in-process end-to-end tests in `internal/testharness` use a mock Tor relay
(`MockRelay`) that faithfully reimplements the server side of the link and
circuit protocols — real TLS link handshake, real ntor server handshake, real
tor1 relay crypto, and real multi-hop extension — so the client packages
exercise the same code paths a real guard/exit would. `TestOneHopFastCircuit`
verifies the `CREATE_FAST` one-hop circuit path against a single mock relay.

The real-network end-to-end test is gated behind the `tor_real` build tag
because it requires outbound connectivity (directly or via the upstream SOCKS5
proxy at `127.0.0.1:7890`) to the Tor directory authorities and real relays,
and a real circuit build can take tens of seconds:

```sh
go test ./internal/testharness/ -tags tor_real \
    -run TestE2ERealTorNetwork -timeout 10m -v
```

## Conformance

Each `internal/` package mirrors specific C source files from the Tor
reference implementation; the package doc comments name the corresponding C
files (e.g. `link` mirrors `src/core/or/connection_or.c` and
`src/core/or/channeltls.c`; `circuit` mirrors `circuitbuild.c`,
`circuitlist.c`, `relay.c`, and `crypt_path_st.h`). See the doc comment at the
top of each package for the precise mapping. A broader architecture overview
is collected in `docs/architecture.md` (where present) alongside the package
docs.

## Authoring

This is an independent Go reimplementation written against the Tor protocol
specifications and the C reference implementation at `../tor` (Tor 0.4.9.x).
No license is claimed on the Tor protocol or the C reference; the Go code in
this repository is authored by the repository contributors.
