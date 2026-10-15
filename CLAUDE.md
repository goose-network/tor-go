# CLAUDE.md — tor-go

A working guide for AI coding agents in this repo.

## What this is

tor-go is a from-scratch Go reimplementation of a Tor client, modeled on the C
reference implementation at `/home/ubuntu/Downloads/proxy/tor` (Tor
0.5.0.0-alpha-dev at HEAD on `main`; the `maint-0.4.9` branch tracks
0.4.9.x). It is a clean-room port: the two repos share **no code**. tor-go
reads the C source as a reference and reimplements the protocols in Go.

- Module: `github.com/goose-network/tor-go`
- Go version: toolchain 1.27.1, but the `go` directive is **1.26.0** so the
  goose repo (which `plugins/tor` is built into) can co-build with
  `GOTOOLCHAIN=go1.26.8` — psiphon-tls panics at init under Go 1.27.x. Build
  goose with
  `cd /home/ubuntu/Downloads/proxy/goose && GOTOOLCHAIN=go1.26.8 go build ./cmd/goose`.
- External dependencies: `golang.org/x/crypto` (curve25519, hkdf, sha3) plus
  `github.com/goose-network/goose-plugin-api` (the published contract module,
  imported only by `plugins/tor` — no local replace; tor-go itself is
  published as v0.0.2 and required by goose the same way).
- Entry point: `cmd/tor-go/main.go` — loads a directory (consensus +
  microdescriptors) from files, or bootstraps one over the network
  (`-fetch-dir`), then serves a SOCKS5 proxy applications connect to.

## Build & test commands

IMPORTANT shell quirk: the Bash tool resets cwd to `/home/ubuntu/Downloads/proxy/tor`
after every command. Prefix every tor-go command with
`cd /home/ubuntu/Downloads/proxy/tor-go && `.

```sh
cd /home/ubuntu/Downloads/proxy/tor-go && go build ./cmd/tor-go     # build the binary
cd /home/ubuntu/Downloads/proxy/tor-go && go build ./...            # build everything
cd /home/ubuntu/Downloads/proxy/tor-go && go test ./...            # run unit + in-process e2e tests
```

The real-network e2e test (`internal/testharness/e2e_real_test.go`) is gated
behind the `tor_real` build tag and is **not** run by `go test ./...`. It needs
outbound connectivity plus an upstream SOCKS5 proxy at `127.0.0.1:7890`, and a
real circuit build can take tens of seconds:

```sh
cd /home/ubuntu/Downloads/proxy/tor-go && go test ./internal/testharness/ -tags tor_real -run TestE2ERealTorNetwork -timeout 10m -v
```

## Architecture in one screen

```
SOCKS5 (socks5)  →  client (torclient)  →  circuits (circuit)  →  link (link)  →  proxy (proxy)
                          ↑                     ↑
                   directory (directory)   guard (guard)
                          ↑
              crypto: ntor / fast / relaycrypto        wire format: torcell
                          ↑
                   testharness (in-process mock relay for e2e tests)
```

- `socks5` is the client-facing entry point (applications configure their
  SOCKS5 proxy here).
- `torclient` owns the directory, the guard link, the SOCKS5 listener, and a
  per-stream circuit builder (it builds a fresh circuit for each stream rather
  than pooling them — strong isolation, simple lifetime); it wires the layers
  together.
- `circuit` builds origin circuits hop by hop (CREATE2/CREATED2,
  EXTEND2/EXTENDED2) and carries relay cells (BEGIN/DATA/CONNECTED/END).
- `link` is the TLS connection to a relay plus the v3 link handshake
  (VERSIONS → CERTS → AUTH_CHALLENGE → AUTHENTICATE → NETINFO).
- `proxy` dials the relay's TCP connection through an upstream SOCKS5 proxy
  before TLS is layered on top.
- `directory` parses and fetches consensus + microdescriptors; `guard` picks
  the first hop (proposal 271).
- `ntor` / `fast` / `relaycrypto` are the crypto primitives; `torcell` is the
  on-the-wire cell format.
- `testharness` is a faithful in-process mock relay server used by e2e tests.

## Package map

Each package's doc comment names the C reference file(s) it mirrors; preserve
that note when editing.

| Package | What it does | Mirrors (C reference) |
|---|---|---|
| `internal/socks5` | SOCKS5 (RFC 1928) server: CONNECT/RESOLVE/RESOLVE_PTR, no-auth + user/pass auth. | `src/core/proto/proto_socks.c` |
| `internal/torclient` | Top-level client: owns directory, guard link, per-stream circuit builder, SOCKS5 listener. | (composition layer; no single C file) |
| `internal/circuit` | Origin circuits: hop-by-hop build + relay-cell dispatch. | `src/core/or/circuitbuild.c`, `circuitlist.c`, `relay.c`, `crypt_path_st.h` |
| `internal/link` | Tor link layer: TLS + v3 link handshake. | `src/core/or/connection_or.c`, `channeltls.c` |
| `internal/link` (certverify.go) | CERTS cell parsing/verification (RSA + ed25519 chains, cross-cert). | `src/feature/nodelist/torcert.c`, `src/trunnel/link_handshake.[ch]`, `src/trunnel/ed25519_cert.[ch]` |
| `internal/proxy` | Outbound dial through an upstream SOCKS5 proxy. | `src/core/or/connection_or.c`, `src/trunnel/socks5.c` |
| `internal/directory` | Parses consensus + microdescriptors into `Router` (which embeds `link.RouterIdentity`). | `src/feature/dirparse/microdesc_parse.c`, `routerparse.c` |
| `internal/directory` (fetch.go) | Fetches real microconsensus + microdescriptors from a dir cache. | `src/feature/dirclient/dirclient.c` |
| `internal/directory` (consensussig.go) | Verifies v3 consensus signatures (majority of dir authorities). | `src/feature/nodelist/networkstatus.c`, `src/feature/dirparse/ns_parse.c`, `src/feature/dirparse/sigcommon.c`, `src/feature/dirparse/authcert_parse.c` |
| `internal/fallback` | Hardcoded fallback directory caches + parser. | `src/app/config/fallback_dirs.inc` |
| `internal/guard` | Guard selection state machine (proposal 271). | `src/feature/client/entrynodes.c`, `entrynodes.h` |
| `internal/ntor` | ntor v1 circuit-extension handshake (Curve25519+HKDF-SHA256). | `src/core/crypto/onion_ntor.c` |
| `internal/ntor` (ntorv3.go) | ntor v3 handshake (proposal 332, SHA3/SHAKE, encrypted onionskin). | `src/core/crypto/onion_ntor_v3.c` |
| `internal/fast` | CREATE_FAST one-hop handshake (SHA-1 TAP key expansion). | `src/core/crypto/onion_fast.c`, `src/lib/crypt_ops/crypto_hkdf.c` |
| `internal/relaycrypto` | Layered AES-128-CTR + SHA-1 running-digest relay-cell crypto. | `src/core/crypto/relay_crypto_tor1.c`, `relay_crypto.c` |
| `internal/torcell` | Wire cell format + cell/relay command constants. | `src/core/or/or.h`, `cell_st.h` |
| `internal/testharness` | In-process mock relay (full server-side reimplementation) for e2e tests. | (test-only; no C mirror) |
| `plugins/tor` | goose provider plugin: wraps tor-go as a `tor` provider for the goose proxy-pool engine (embeds internal/torclient + internal/directory, exposes one `socks5` outbound at tor-go's loopback listener). | (plugin adapter; no C mirror) |

## Key conventions

- **Every package doc comment names the C reference file it mirrors.** Preserve
  this when editing or adding a package.
- **Cell commands and relay commands are constants in `internal/torcell/cell.go`**
  (e.g. `CellCreate2`, `CellCreated2`, `RelayBegin`, `RelayData`, `RelayEnd`,
  `RelayExtend2`, `RelayBeginDir`, `RelaySendme`). Reuse them; do not hardcode
  magic numbers.
- **The mock relay (`testharness`) is a faithful server-side reimplementation,
  not a stub.** e2e tests exercise the real client code paths (link handshake,
  circuit build, relay dispatch) against it.
- **Config defaults** (see `torclient.Config`): SOCKS5 listener, `PathLen` 3
  (guard/middle/exit), private-address rejection **ON** by default
  (`AllowPrivateAddresses=false`).
- **Port semantics — do not confuse these:**
  - `7890` is the **upstream** SOCKS5 proxy that tor-go dials *through* to reach
    relays and directory authorities (e.g. a local Clash/V2Ray instance).
  - `1080` is tor-go's **own** SOCKS5 listener that applications connect to.
  - The `torclient` package doc and `Config.SocksAddr` default mention `7890`
    as a listener default in the example, but `cmd/tor-go`'s `-socks` flag
    defaults to `127.0.0.1:1080` and `-upstream` is the 7890 dial-through.
    When wiring the binary, 1080 = listener, 7890 = upstream.

## Where to make common changes

- **Add a new relay cell command**: add the constant in `internal/torcell/cell.go`,
  then add dispatch in `internal/circuit` (relay-cell handling) and, if the
  mock relay must support it for tests, the server-side handling in
  `internal/testharness`.
- **Add a SOCKS5 feature**: implement in `internal/socks5`, then wire it through
  `internal/torclient` (the `dialer` and `Config`).
- **Add a directory fetch path**: edit `internal/directory/fetch.go` (or
  `fetchcircuit.go` if present); the fetcher is invoked from
  `cmd/tor-go/main.go` via `directory.Fetch` and from `torclient` bootstrap.
- **Add a circuit handshake**: add a crypto package alongside `fast`/`ntor`,
  then wire it into `internal/circuit`'s hop-build switch (CREATE2/EXTEND2
  payload construction and CREATED2/EXTENDED2 reply parsing).

## Testing strategy

- **Unit tests per package** (`*_test.go` next to the code), no network.
- **In-process e2e** via `testharness.NewHarness(n)`, which starts a chain of
  `n` mock relays (guard, middle, ..., exit) on ephemeral loopback ports with
  generated TLS certs and onion keys. Tests build a real client against the
  harness directory and exercise the full SOCKS5 → circuit → relay path.
  - `TestOneHopFastCircuit` (`fast_circuit_test.go`) uses a 1-relay harness to
    verify the CREATE_FAST one-hop path.
  - `TestLinkHandshake` (in `integration_test.go`) and the e2e tests in
    `e2e_test.go` use multi-relay harnesses; they set
    `AllowPrivateAddresses: true` because the mock exit targets a loopback
    origin server.
- **Real-network e2e** (`e2e_real_test.go`, build tag `tor_real`) is separate
  and usually skipped (see Build & test commands).

## Do NOT

- Claim the C repo and tor-go share code — they don't; tor-go is a clean-room
  reimplementation that reads the C source only as a reference.
- Invent packages, flags, or constants that are not in this repo — check
  `internal/` and `cmd/tor-go/main.go` first.
- Modify the C reference repo at `/home/ubuntu/Downloads/proxy/tor`. It is
  read-only reference material.
