# Architecture

This document describes the layered architecture of `tor-go`, the data flow of
a typical request, and how each subsystem conforms to the Tor protocol as
implemented by the C reference at `/home/ubuntu/Downloads/proxy/tor` (Tor
`0.5.0.0-alpha-dev` on `main`; the `maint-0.4.9` branch tracks 0.4.9.x). It is
a companion to the per-package reference in `packages.md` and the package doc
comments, which are the authoritative source for symbol-level detail.

## Overview

`tor-go` is a layered reimplementation of a Tor client. The layers, from the
outside in:

```
   application (curl, browser, …)
            │  SOCKS5
            ▼
   socks5  ─────────── client-facing entry point (CONNECT/RESOLVE/RESOLVE_PTR)
            │
            ▼
   torclient  ──────── orchestration: directory, guard, per-stream circuits
            │
            ▼
   circuit  ────────── origin circuits: hop-by-hop build + relay-cell dispatch
            │
            ▼
   link  ────────────── TLS connection to a relay + v3 link handshake
            │
            ▼
   proxy  ───────────── outbound dial through an upstream SOCKS5 proxy
            │
            ▼
   Tor network ──► target
```

Support packages sit alongside these layers:

- **directory** — parses and fetches consensus + microdescriptors; verifies
  consensus signatures.
- **guard** — picks the first hop (proposal 271).
- **fallback** — hardcoded fallback directory caches for bootstrap.
- **ntor** / **fast** / **relaycrypto** — the circuit-handshake and relay-cell
  crypto primitives.
- **torcell** — the on-the-wire cell format and command constants.
- **testharness** — an in-process mock relay for end-to-end tests.

## Data flow of a SOCKS5 CONNECT

A request from an application (e.g. `curl --socks5-hostname 127.0.0.1:1080`)
travels through the layers as follows:

1. **SOCKS5 accept** — `socks5.Server.ListenAndServe` accepts a connection,
   reads the SOCKS5 greeting, selects an auth method (no-auth `0x00` or
   userpass `0x02`), reads the request. For CONNECT it extracts the target
   `host:port`. If `RejectPrivateAddresses` is set, private/loopback/link-local
   targets (and `localhost`/`*.local`) are refused before any Tor work.
2. **Dial through Tor** — the server calls `Dialer.DialStream(ctx, target)`,
   implemented by `torclient`'s `dialer`. The dialer builds a **fresh circuit
   for this stream** (`circuit.New` with a guard/middle/exit path selected from
   the directory), opens a stream on it, and returns the `Stream` as an
   `io.ReadWriteCloser`.
3. **Circuit build** — `circuit.New` dials the guard (`link.Dial` /
   `link.DialWithUpstream`), completes the v3 link handshake, sends CREATE2
   (ntor v1 or v3) for the first hop, then EXTEND2 for each subsequent hop
   (middle, exit), installing a `relaycrypto.Layer` per hop as each CREATED2 /
   EXTENDED2 reply arrives.
4. **BEGIN** — `Circuit.OpenStream` sends a RELAY_BEGIN cell (encrypted with
   the exit's layer) to the exit, carrying the target and IPv6 flags. The exit
   dials the target and replies RELAY_CONNECTED (with the bound IPv4/IPv6
   address) or RELAY_END (on failure).
5. **Data** — the application's bytes are written to the `Stream`
   (`Stream.Write` → RELAY_DATA, encrypted layer by layer toward the exit);
   responses arrive as RELAY_DATA cells, decrypted layer by layer toward the
   client, and are returned by `Stream.Read`. Flow control is enforced via
   circuit/stream windows and SENDMEs (below).
6. **End** — when either side closes, a RELAY_END (reason DONE = 6) is sent;
   the client surfaces this as `circuit.ErrEOF`, which the SOCKS5 layer
   translates to a normal connection close. END reasons are mapped to SOCKS5
   reply codes (e.g. connection refused → `ErrConnRefused`).

## Link layer

A `link.Link` is a TLS connection to a relay plus the completed v3 link
handshake. The handshake (`link.go`, mirroring `connection_or.c` /
`channeltls.c`) is:

- **VERSIONS** — the client sends its supported link protocol versions; the
  highest common version (≥ `MinLinkProtocol = 4`) is selected, fixing the
  circuit-ID width to 4 bytes.
- **CERTS** — the relay sends its certificate cell. `certverify.go` parses and
  verifies it: the ed25519 cert chain (self-signed ID cert, signing→link cert
  bound to the SHA-256 of the TLS peer cert DER), the RSA cert chain, and the
  RSA→ed25519 cross-cert (SHA-256 of prefix+ed_key+expiration, PKCS#1 v1.5).
  It records the relay's ed25519 and RSA identities and checks the RSA digest
  against the expected digest. A degenerate CERTS (used by the mock relay)
  falls back to a legacy TLS-cert SHA-1 digest check.
- **AUTH_CHALLENGE** — the client receives and drains this; as a client it does
  **not** send AUTHENTICATE (only the relay authenticates to the client).
- **NETINFO** — timestamps and addresses are exchanged. The client parses the
  peer's 4-byte timestamp, records `PeerTimestamp` / `ClockSkew`, and warns at
  |skew| > 3600s (`NETINFO_NOTICE_SKEW`).

After the handshake, `Link.Register` allocates circuit IDs and a channel for
inbound cells; `Link.Send` writes cells; the read loop dispatches cells to the
registered circuit channels.

## Circuit handshakes

`circuit` builds circuits hop by hop. Three handshakes are supported:

- **ntor v1** (`ntor-curve25519-sha256-1`, `ntor.go`, mirrors `onion_ntor.c`):
  CREATE2/CREATED2. The client's `ClientHandshake` verifies the server MAC (the
  real handshake authentication) and derives `TotalKeyLen` bytes; the trailing
  KH is the rend-circ nonce, sanity-checked for non-zero.
- **ntor v3** (proposal 332, `ntorv3.go`, mirrors `onion_ntor_v3.c`):
  `ntor3-curve25519-sha3_256-1`, using SHA3-256 + SHAKE-256 + AES-256-CTR, the
  "circuit extend" verification string, and ENCAP length-prefixing. Selected
  when the relay advertises `Relay>=4` **and** has a non-zero ed25519 identity;
  otherwise v1 is used.
- **CREATE_FAST** (`fast.go`, mirrors `onion_fast.c`): a one-hop,
  non-forward-secure SHA-1-based handshake used only for directory bootstrap.
  The client sends a 20-byte nonce `x`; the server replies `y || H(x||y)` (40
  bytes), where `H` is the TAP key expansion
  (`SHA1(key_in||0) || SHA1(key_in||1) || …`, `key_in = x||y`). The client
  verifies the integrity check (constant-time) and derives the key material.
  This is safe only because the TLS link already authenticates the relay and
  the relay's identity is verified from its TLS certificate; it must never be
  used beyond the first hop.

`circuit.New` uses ntor (v3 or v1) for the first hop and EXTEND2 for subsequent
hops; `circuit.NewOneHopFast` uses CREATE_FAST for a one-hop directory circuit.

## Multi-hop extension

Subsequent hops are added with RELAY_EXTEND2 / RELAY_EXTENDED2
(`circuit.go`, mirrors `circuitbuild.c`). The EXTEND2 payload is a list of link
specifiers followed by a CREATE2 payload. `buildLinkSpecifiers` constructs:

- type 1 — IPv4 address + port (4 + 2 bytes),
- type 2 — legacy RSA identity digest (20 bytes),
- type 3 — ed25519 identity (32 bytes, when non-zero).

The relay at the current hop extends the circuit to the next relay and returns
EXTENDED2, from which the next hop's `relaycrypto.Layer` is installed.
RELAY_EARLY is used for extension cells and capped at
`MaxRelayEarlyCellsPerCircuit = 8` per circuit; the client refuses to extend
once exhausted.

## Relay crypto

`relaycrypto` (mirrors `relay_crypto_tor1.c` / `relay_crypto.c`) implements the
"tor1" layered crypto. Each hop owns a forward AES-128-CTR cipher + SHA-1
running digest (sending toward that hop) and a backward cipher + digest
(receiving from that hop). Cells leaving the client are encrypted with every
layer from the exit hop inward to the guard; cells returning are decrypted and
authenticated layer by layer. Key lengths: `KeyMaterialLen` (2 digests + 2
cipher keys per hop), `KHLen` (the rend-circ nonce), `TotalKeyLen = 92`.
`NewLayer` builds the origin-side layer; `NewLayerReversed` builds the
server-side (mock) layer.

## Flow control

`circuit` enforces windowed flow control (mirrors `relay.c`):

- **Circuit-level window**: `CIRCWINDOW_START = 1000`,
  `CIRCWINDOW_INCREMENT = 100`. The client's deliver window counts down as
  DATA cells arrive; when it drops to `CIRCWINDOW_START - CIRCWINDOW_INCREMENT`
  (900) a circuit-level SENDME is sent to refill it.
- **Stream-level window**: `STREAMWINDOW_START = 500`,
  `STREAMWINDOW_INCREMENT = 50`, refilled analogously.
- **SENDME authentication** (proposal 289): each SENDME carries a 4-byte digest
  tag (`relaycrypto.Layer.SendmeTag`) so the recipient can verify the SENDME
  came from the peer that received the data.
- **Package window**: the client's package window bounds outbound DATA cells;
  it blocks `Stream.Write` when exhausted and is refilled by inbound SENDMEs.

## Directory

`directory` provides parsing, fetching, and signature verification.

- **Parsing** (`directory.go`, mirrors `microdesc_parse.c` / `routerparse.c`):
  `ParseConsensus` parses the `r`/`m`/`a` consensus lines into `Router` values
  (which embed `link.RouterIdentity`); `ParseMicrodescriptors` parses
  `onion-key`/`ntor-onion-key`/`p`/`pr` microdescriptor lines and merges them.
  `ParseShortPolicy` and `ParseProtoVer` parse exit policies and protocol
  versions.
- **Fetching** (`fetch.go`, mirrors `dirclient.c`): two paths.
  - **HTTPS to authorities** — `Fetch`/`FetchWithMeta` download the
    microconsensus and microdescriptors from a directory authority, tunneled
    through the configured upstream proxy. `FetchOptions.Retries` adds
    exponential backoff (1/2/4/…/30s) across authorities.
  - **One-hop fallback circuit** (`fetchcircuit.go`, `UseFallbacks = true`) —
    the C client's primary bootstrap path: dial a fallback relay's ORPort over
    TLS (verifying its RSA fingerprint via `link.DialWithUpstream`), build a
    one-hop CREATE_FAST circuit, BEGIN_DIR, and HTTP/1.1 GET the consensus
    (`/tor/status-vote/current/consensus-microdesc`) and microdescriptors
    (`/tor/micro/d/<hex>`) over the stream. Fallbacks are tried in order until
    one succeeds.
- **Consensus signature verification** (`consensussig.go`, mirrors
  `networkstatus.c` / `ns_parse.c` / `sigcommon.c` / `authcert_parse.c`):
  parses `directory-signature` footer blocks, computes the consensus signed
  digest (SHA-1 from `network-status-version` through the trailing
  `directory-signature ` space), parses authority certs
  (`dir-key-certificate-version 3`, self-signed by the identity key), verifies
  each signature with the authority's signing key, and requires a quorum of
  `n_v3_authorities/2 + 1` (= 5 of 9) good signatures from trusted authorities.
  Enabled via `FetchOptions.VerifySignatures` (off by default for test
  compatibility; should be on for real use).

## Guard selection

`guard` (mirrors `entrynodes.c`, proposal 271) picks the first hop. The state
machine keeps:

- a bounded **sample** (≤ 20% of eligible guards, min 20, max 60),
- a **filtered** subset that passes the current configuration,
- a small set of **primary** guards (default 3) preferred for use,
- a **confirmed** list of guards used successfully.

`PickForCircuit` follows the prop271 order: primary → confirmed → filtered
sample, expanding the sample if it is too small. `NoteConnectionSuccess` /
`NoteConnectionFailure` drive confirmation and retry scheduling;
`UpdateListing` drops guards unlisted for more than 20 days. Wired into
`torclient` with failover: on guard dial failure the guard is marked failed and
the next is tried (up to 5 attempts); on success it is confirmed. A pinned
`Config.Guard` bypasses the manager.

## Security controls

- **Private-address rejection** (`socks5`, mirrors `tor_addr_is_internal_` in
  `address.c`): when `RejectPrivateAddresses` / `Config.AllowPrivateAddresses =
  false` (the default), SOCKS5 targets that are private, loopback, link-local,
  or `localhost`/`*.local` are refused, and port-0 is rejected unconditionally.
- **`.onion` refusal**: the SOCKS5 layer refuses `.onion` targets with "command
  not supported" (full hidden-service support is out of scope).
- **END-reason → SOCKS5 mapping**: `circuit`'s `endReasonToError` maps relay END
  reasons to exported errors (`ErrConnRefused`, `ErrHostUnreachable`, …), which
  `socks5` maps to the appropriate SOCKS5 reply code.
- **Identity verification**: the relay's RSA and ed25519 identities are
  verified from the CERTS cell during the link handshake; fallback relays are
  verified by RSA fingerprint against their TLS certificate.

## Test architecture

`testharness` provides an in-process mock Tor relay (`MockRelay`) that is a
faithful server-side reimplementation — real TLS link handshake, real ntor
server handshake, real CREATE_FAST server handshake, real tor1 relay crypto
(reversed layers), and real multi-hop extension. `NewHarness(n)` starts a chain
of `n` mock relays on ephemeral loopback ports with generated TLS certs and
onion keys, plus a directory the client can use.

- **Unit tests** per package (`*_test.go`), no network.
- **In-process e2e** via the harness: `TestOneHopFastCircuit` (1-relay harness,
  CREATE_FAST one-hop path), `TestLinkHandshake` (in `integration_test.go`), and
  the e2e tests in `e2e_test.go` (multi-relay harnesses, with
  `AllowPrivateAddresses: true` so the mock exit can target a loopback origin).
- **Real-network e2e** (`e2e_real_test.go`, build tag `tor_real`): requires
  outbound connectivity (directly or via the upstream SOCKS5 proxy at
  `127.0.0.1:7890`) to real authorities and relays; usually skipped.

## Conformance summary

| Subsystem | tor-go package | C reference | Status |
|---|---|---|---|
| Wire cell format | `torcell` | `or.h`, `cell_st.h` | Implemented |
| Upstream SOCKS5 dial | `proxy` | `connection_or.c`, `trunnel/socks5.c` | Implemented (SOCKS5, no auth) |
| Link layer + v3 handshake | `link` | `connection_or.c`, `channeltls.c` | Implemented (client side; no AUTHENTICATE) |
| CERTS verification | `link/certverify.go` | `torcert.c`, `trunnel/link_handshake.[ch]`, `trunnel/ed25519_cert.[ch]` | Implemented |
| NETINFO skew detection | `link` | `channeltls.c` | Implemented |
| ntor v1 handshake | `ntor` | `onion_ntor.c` | Implemented |
| ntor v3 handshake | `ntor/ntorv3.go` | `onion_ntor_v3.c` | Implemented |
| CREATE_FAST handshake | `fast` | `onion_fast.c`, `crypto_hkdf.c` | Implemented |
| Relay crypto (tor1) | `relaycrypto` | `relay_crypto_tor1.c`, `relay_crypto.c` | Implemented |
| Origin circuits + EXTEND2 | `circuit` | `circuitbuild.c`, `circuitlist.c`, `relay.c`, `crypt_path_st.h` | Implemented |
| SENDME flow control | `circuit`, `relaycrypto` | `relay.c` (prop 289) | Implemented |
| Directory parsing | `directory` | `microdesc_parse.c`, `routerparse.c` | Implemented |
| Directory fetch (HTTPS) | `directory/fetch.go` | `dirclient.c` | Implemented |
| Directory fetch (fallback circuit) | `directory/fetchcircuit.go` | `dirclient.c` | Implemented |
| Fallback directory list | `fallback` | `fallback_dirs.inc` | Implemented |
| Consensus signature verification | `directory/consensussig.go` | `networkstatus.c`, `ns_parse.c`, `sigcommon.c`, `authcert_parse.c` | Implemented |
| Guard selection (prop 271) | `guard` | `entrynodes.c`, `entrynodes.h` | Implemented |
| SOCKS5 entry | `socks5` | `proto_socks.c` | Implemented (CONNECT/RESOLVE/RESOLVE_PTR, no-auth + userpass) |
| Client orchestration | `torclient` | (composition) | Implemented |
| Bridges / pluggable transports | — | `transports/` | Out of scope |
| Hidden services | — | `rendcommon.c`, `hs_*.c` | Out of scope (`.onion` refused) |
| Link/circuit padding | — | `padding.c` | Out of scope |
| Congestion control (beyond SENDME) | — | `congestion_control*.c` | Out of scope |
