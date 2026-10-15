# Package reference

This document is a per-package reference for `tor-go`'s `internal/` packages,
the `cmd/tor-go` entry point, and the `plugins/tor` goose provider plugin.
Packages are listed bottom-up in dependency order
(wire format and crypto primitives first, then the layers that compose them,
then the top-level client and the test harness). For each package it gives the
purpose, the C reference file(s) it mirrors, the key exported API, and notable
behavior or security caveats. The authoritative source for any detail is always
the package's own doc comment and code.

## torcell

**Purpose:** the on-the-wire cell format. All inter-relay channel traffic is
carried in fixed-size cells (514 bytes: 4-byte circuit ID + 1-byte command +
509-byte payload on modern link-protocol-≥4 links).

**Mirrors:** `src/core/or/or.h`, `src/core/or/cell_st.h`.

**Key API:**

- `Cell` — a fixed-size cell: `CircID uint32`, `Cmd uint8` (a `Cell*` constant),
  `Payload [509]byte`.
- `VarCell` — a variable-length cell: `CircID uint32`, `Cmd uint8`, `Payload []byte`.
- `Codec` — reads and writes cells on an `io.ReadWriter`.
  - `NewCodec(rw, circIDWidth) *Codec`
  - `ReadCell() (*Cell, error)`, `ReadVarCell() (*VarCell, error)`,
    `ReadAny() (interface{}, error)`
  - `WriteCell(*Cell) error`, `WriteVarCell(*VarCell) error`
  - `CircIDWidth() int`, `SetCircIDWidth(int)`
- `IsVariable(cmd uint8) bool` — whether a command uses variable-length cells.
- Cell command constants: `CellPadding`, `CellCreate`, `CellCreated`, `CellRelay`,
  `CellDestroy`, `CellCreateFast`, `CellCreatedFast`, `CellVersions`,
  `CellNetinfo`, `CellRelayEarly`, `CellVPadding`, `CellCerts`,
  `CellAuthChallenge`, `CellAuthenticate`, `CellAuthorize`,
  `CellPaddingNegotiate`.
- Relay command constants: `RelayBegin`, `RelayData`, `RelayEnd`,
  `RelayConnected`, `RelaySendme`, `RelayExtend`, `RelayExtended`,
  `RelayTruncate`, `RelayTruncated`, `RelayDrop`, `RelayResolve`,
  `RelayResolved`, `RelayBeginDir`, plus conflux/padding/intro/rendezvous
  constants defined for completeness.
- Size constants: `PayloadSize = 509`, `CircIDWidth4 = 4`, `CircIDWidth3 = 2`,
  `TotalSize4`, `TotalSize3`, `RelayHeaderSize = 11`,
  `RelayPayloadSizeMax = PayloadSize - RelayHeaderSize`.

**Notes:** The circuit-ID width is negotiated during the VERSIONS handshake
(width 4 for link protocol ≥ 4); the codec is reconfigured accordingly.

## proxy

**Purpose:** outbound connection helper that dials a relay's TCP connection
through an upstream SOCKS5 proxy (e.g. a local Clash/V2Ray instance at
`127.0.0.1:7890`), before TLS and the Tor link handshake are layered on top.

**Mirrors:** `src/core/or/connection_or.c` (SOCKS proxy support), with the
SOCKS5 wire format from `src/trunnel/socks5.c`. Restricted to SOCKS5 with no
authentication.

**Key API:**

- `Dial(ctx, upstreamAddr, addr) (net.Conn, error)` — connects to `addr`
  (host:port) by issuing a SOCKS5 CONNECT through the upstream proxy at
  `upstreamAddr`. (See the package source for the exact signature.)

**Notes:** Empty `upstreamAddr` means dial directly. This is the only package
that knows about the upstream proxy; the link layer calls it to obtain the raw
TCP connection.

## ntor

**Purpose:** the ntor circuit-extension handshake (`ntor-curve25519-sha256-1`),
a one-way authenticated key exchange based on Curve25519 (X25519), HMAC-SHA256,
and HKDF-SHA256, used to establish per-hop circuit keys. Provides both ntor v1
and ntor v3.

**Mirrors:** `src/core/crypto/onion_ntor.c` (v1) and
`src/core/crypto/onion_ntor_v3.c` (v3).

**Key API (v1):**

- `PROTOID = "ntor-curve25519-sha256-1"`, `OnionskinLen = 84`, `ReplyLen = 64`.
- `ClientState` — in-progress client handshake state.
- `Create(routerID, routerKey []byte) (onionskin []byte, state *ClientState, err error)`
  — builds the CREATE2 onionskin (client ephemeral key + router ID/key).
- `(s *ClientState) ClientHandshake(reply []byte, keyLen int) (keys []byte, err error)`
  — completes the handshake, verifying the server MAC and deriving `keyLen`
  bytes of key material.

**Key API (v3 — proposal 332):**

- `V3OnionskinMinLen = 128`, `V3ReplyMinLen = 64`, `V3KeyMaterialLen = 92`.
- `V3ClientState` — in-progress v3 client handshake state.
- `V3Create(edID, routerKey []byte) (onionskin []byte, state *V3ClientState, err error)`
  — builds the encrypted v3 onionskin (ntor3-curve25519-sha3_256-1).
- `(s *V3ClientState) V3ClientHandshake(reply []byte, keyLen int) (keys []byte, err error)`
  — completes the v3 handshake (SHA3-256 + SHAKE-256 + AES-256-CTR, with the
  "circuit extend" verification string and ENCAP length-prefixing).

**Key API (server side, for tests):**

- `ServerKeyPair` — a relay's static ntor key pair (Curve25519 + router ID).
- `GenerateServerKeyPair(routerID [digestLen]byte) (*ServerKeyPair, error)`
- `ServerHandshake(onionskin []byte, kp *ServerKeyPair, keyLen int) (reply, keys []byte, err error)`

**Notes:** The circuit layer selects v3 when a relay advertises `Relay>=4` and
has an ed25519 identity, falling back to v1 otherwise. The v1 client handshake
performs the real MAC verification that authenticates the handshake; the
trailing KH bytes are the rend-circ nonce, sanity-checked for non-zero.

## fast

**Purpose:** the `CREATE_FAST` circuit handshake — an unauthenticated,
non-forward-secure SHA-1-based key derivation used only for the first hop of a
one-hop circuit to a trusted directory cache.

**Mirrors:** `src/core/crypto/onion_fast.c`, with the TAP key expansion from
`src/lib/crypt_ops/crypto_hkdf.c` (`crypto_expand_key_material_TAP`).

**Key API:**

- `NonceLen = 20`, `ReplyLen = 40` (`NonceLen*2`).
- `State` — the client's in-progress handshake state (the nonce `x` it sent).
- `Create() (onionskin []byte, state *State, err error)` — generates the random
  nonce `x` (the CREATE_FAST onionskin).
- `(s *State) ClientHandshake(reply []byte, keyLen int) (keys []byte, err error)`
  — verifies the integrity check (`H(x||y)`, constant-time) and derives
  `keyLen` bytes of key material.
- `ServerHandshake(onionskin []byte, keyLen int) (reply, keys []byte, err error)`
  — server side: generates `y`, returns the CREATED_FAST reply (`y || H(x||y)`)
  and the derived keys. Exported so the in-process test relay can share the
  canonical TAP expansion.

**Notes / security:** CREATE_FAST is safe only because the TLS link to the
relay already authenticates it (the relay's identity is verified from its TLS
certificate) and protects the handshake from eavesdroppers. It must never be
used for a hop beyond the first, or to a relay whose identity is not
independently verified. The TAP expansion is
`output = SHA1(key_in || 0) || SHA1(key_in || 1) || …` truncated, where
`key_in = x || y`.

## relaycrypto

**Purpose:** the layered encryption and integrity protection applied to relay
cells as they travel along a circuit — the "tor1" relay crypto. Each hop owns a
forward AES-128-CTR cipher + SHA-1 running digest (sending toward that hop) and
a backward cipher + digest (receiving from that hop).

**Mirrors:** `src/core/crypto/relay_crypto_tor1.c` and the key layout in
`src/core/crypto/relay_crypto.c`.

**Key API:**

- `KeyMaterialLen` — key bytes consumed by one hop (2 digests + 2 cipher keys).
- `KHLen` — trailing handshake-authenticator length (the rend-circ nonce).
- `TotalKeyLen = KeyMaterialLen + KHLen` — the full amount an ntor/fast client
  handshake must derive for one hop (92 bytes).
- `SendmeTagLen = 4`.
- `Layer` — one hop's relay crypto layer.
  - `NewLayer(keyMaterial []byte) (*Layer, error)` — origin-side layer
    (forward = encrypt-then-send).
  - `NewLayerReversed(keyMaterial []byte) (*Layer, error)` — server-side layer
    (reversed: backward = the direction the origin calls forward).
  - `(l *Layer) SendmeTag() [SendmeTagLen]byte` — the prop-289 SENDME digest
    tag, used to authenticate circuit/stream SENDMEs.
- `VerifyKH(expected, reply []byte) error` — constant-time KH comparison.
- `EncodeRelayEndReason(reason uint8) []byte`, `DecodeRelayEndReason(b []byte) (uint8, error)`.
- `EncodeUint16(v uint16) []byte`.

**Notes:** Cells leaving the client are encrypted with every layer from the
exit hop inward to the guard; cells returning are decrypted and authenticated
layer by layer.

## link

**Purpose:** the Tor link layer — a TLS connection to a relay plus the v3 link
handshake. After the handshake, the `Link` exposes a cell channel over which
circuits are built.

**Mirrors:** `src/core/or/connection_or.c`, `src/core/or/channeltls.c`; CERTS
verification in `certverify.go` mirrors `src/feature/nodelist/torcert.c`,
`src/trunnel/link_handshake.[ch]`, `src/trunnel/ed25519_cert.[ch]`.

**Key API:**

- `MinLinkProtocol = 4`, `MaxCellSize`.
- `Link` — an established TLS link to a relay.
  - `Dial(ctx, addr, expectedIDDigest []byte) (*Link, error)` — direct TLS
    dial, verifying the relay's RSA identity digest.
  - `DialWithUpstream(ctx, upstreamAddr, addr, expectedIDDigest []byte) (*Link, error)`
    — same, but the TCP connection is established through the upstream SOCKS5
    proxy (used for fallback-directory bootstrap).
  - `Register() (circID uint32, ch <-chan *torcell.Cell, err error)` — allocate
    a circuit ID and a channel for inbound cells on that circuit.
  - `Unregister(id uint32)`, `Send(cell *torcell.Cell) error`.
  - `Protocol() uint16`, `PeerRSAIDDigest() [20]byte`,
    `PeerEd25519ID() ([32]byte, bool)`, `RemoteAddr() net.Addr`.
  - `Close() error`, `Wait() error`.
- `RouterIdentity` — a relay's identity as parsed from the directory:
  `Nickname`, `IDDigest [20]byte`, `Ed25519ID [32]byte`, `OnionKey [32]byte`
  (Curve25519 ntor key), `Address string`, `ProtoVer map[string]string`
  (parsed "pr" line; `Relay>=4` selects ntor v3).
- `ErrClosed`.

**Notes:** As a client, tor-go receives and verifies the relay's CERTS cell
(ed25519 cert chain, RSA chain, RSA→ed25519 cross-cert, with a legacy TLS-cert
SHA-1 digest fallback for degenerate CERTS), drains AUTH_CHALLENGE, and sends
NETINFO — it does not send AUTHENTICATE (only the relay authenticates to the
client). NETINFO timestamp parsing records `PeerTimestamp`/`ClockSkew` and warns
at |skew| > 3600s.

## guard

**Purpose:** the guard-selection state machine from Tor proposal 271, which
picks the first hop of every circuit. Keeps a persistent, bounded *sample* of
guard relays, filters it, marks a small number of *primary* guards, and records
*confirmed* guards used successfully.

**Mirrors:** `src/feature/client/entrynodes.c` (`entry_guards_expand_sample`,
`entry_guards_update_primary`, `select_entry_guard_for_circuit`,
`entry_guard_consider_retry`, `entry_guard_relayed_succeeded`) and the
`entry_guard_t` / `guard_selection_t` structures in `entrynodes.h`.

**Key API:**

- `Guard` — a guard entry: `ID` (hex RSA identity digest), sample/confirm
  timestamps and indices, retry/failure state, and prop271 state flags
  (`IsPrimary`, `IsFilteredGuard`, `IsUsableFilteredGuard`, `CurrentlyListed`,
  `IsReachable`, …).
- `Selection` — a pick result: `Guard *Guard` and `UsableOnCompletion bool`
  (true for primary guards — usable as soon as the circuit completes; false for
  fallback guards — usable only if no better guard works).
- `Params` — tunables: `MaxSampleThresholdPercent`, `MaxSampleSize`,
  `MinFilteredSampleSize`, `NPrimaryGuards`, `GuardLifetimeDays`,
  `RemoveUnlistedAfterDays`.
- `Manager` — the state machine.
  - `NewManager(p Params) *Manager`.
  - `ExpandSample(eligible []EligibleGuard, now time.Time)` — grow the sample
    up to the configured cap.
  - `PickForCircuit(eligible []EligibleGuard, now time.Time) *Selection` —
    pick following the prop271 order (primary → confirmed → filtered sample,
    expanding if empty).
  - `NoteConnectionSuccess(id string, now)`, `NoteConnectionFailure(id string, now)`.
  - `UpdateListing(listedIDs map[string]bool, now time.Time) int` — drop guards
    unlisted for too long.
  - `Primary() []*Guard`, `Sampled() []*Guard`, `Confirmed() []*Guard`,
    `Lookup(id string) *Guard`.
- `EligibleGuard` — an eligible relay fed to the manager.

**Notes:** Wired into `torclient.New`/`Connect` with failover: on guard dial
failure the guard is marked failed and the next is tried (up to 5 attempts); on
success it is confirmed. A pinned `Config.Guard` bypasses the manager.

## fallback

**Purpose:** the hardcoded list of fallback directory caches and a parser for
its line format. A fallback serves directory documents to clients that have not
yet obtained a consensus; the client bootstraps by contacting a fallback over a
one-hop CREATE_FAST circuit with BEGIN_DIR, falling over to the next on failure.

**Mirrors:** `src/app/config/fallback_dirs.inc`.

**Key API:**

- `Fallback` — a fallback entry: `IPv4Addr`, `IPv6Addr` (host:port / `[addr]:port`),
  `RSAFingerprint [20]byte`.
  - `HexFingerprint() string`, `PreferredAddr() string` (IPv6 preferred when
    present).
- `DefaultFallbacks` — a curated list of real fallback relays.
- `Parse(data []byte) ([]Fallback, error)` — parse the `fallback_dirs.inc`
  format (comma-separated entries, quoted string fragments, `/* */` comments,
  `orport=`/`id=`/`ipv6=` tokens).

**Notes / security:** The list carries only ORPorts and RSA fingerprints — no
onion keys — because the identity is verified against the relay's TLS
certificate during the link handshake (`link.DialWithUpstream`), so CREATE_FAST's
lack of forward secrecy is acceptable for a one-hop directory circuit. The
curated list goes stale as relays churn; `Parse` lets it be regenerated from a
current `fallback_dirs.inc`.

## directory

**Purpose:** parses Tor directory documents (microconsensus + microdescriptors)
into `Router` values the link and circuit layers use, and fetches real
directory documents over HTTPS (to authorities) or over a one-hop CREATE_FAST
circuit to a fallback (BEGIN_DIR). Also verifies v3 consensus signatures.

**Mirrors:** `src/feature/dirparse/microdesc_parse.c`, `routerparse.c`
(parsing); `src/feature/dirclient/dirclient.c` (fetching);
`src/feature/nodelist/networkstatus.c`, `src/feature/dirparse/ns_parse.c`,
`src/feature/dirparse/sigcommon.c`, `src/feature/dirparse/authcert_parse.c`
(consensus signature verification).

**Key API — parsing (`directory.go`):**

- `Router` — a parsed relay; embeds `link.RouterIdentity` and adds
  `MicrodescDigest [32]byte` (and exit-policy / protover fields populated from
  the microdescriptor).
- `ConsensusMeta` — validity timestamps extracted from a consensus.
  - `ParseConsensusMeta(text []byte) (*ConsensusMeta, error)`.
- `ParseConsensus(text []byte) (map[string]*Router, error)` — parse the
  `r`/`m`/`a` consensus lines.
- `ParseMicrodescriptors(text []byte, routers map[string]*Router) error` — parse
  `onion-key`/`ntor-onion-key`/`p`/`pr` lines and merge into `routers`.
- `ParseShortPolicy(summary string) *ShortPolicy` — parse a short exit policy.
- `ParseProtoVer(s string) map[string]string` — parse a "pr" line.
- `SelectGuard(routers) (*Router, error)`, `SelectExit(routers) (*Router, error)`,
  `SelectMiddle(routers) (*Router, error)` — bandwidth-weighted path selection.

**Key API — fetching (`fetch.go`):**

- `DirectoryAuthority` — a fetch source: `Name`, `ConsensusURL`,
  `MicrodescURL func(hexDigest string) string`, `CertURL func(hexFingerprint string) string`.
- `DefaultAuthorities` — the hardcoded v3 directory authorities.
- `FetchOptions` — `UpstreamProxy`, `Authorities`, `Timeout`, `MaxMicrodescs`,
  `VerifySignatures`, `Retries` (exponential backoff 1/2/4/…/30s), `UseFallbacks`
  (bootstrap over a one-hop CREATE_FAST circuit to a fallback instead of HTTPS).
- `Fetch(ctx, opts) (map[string]*Router, error)`,
  `FetchWithMeta(ctx, opts) (map[string]*Router, *ConsensusMeta, error)`.

**Key API — consensus signatures (`consensussig.go`):**

- `AuthorityCert` — a parsed dir-authority certificate (`dir-key-certificate-version 3`).
- `ConsensusSignature` — a parsed `directory-signature` block.
- `TrustedV3AuthorityDigests` — the trusted v3 authority identity digests.
- `NumTrustedV3Authorities() int`, `ConsensusQuorum() int` (`n/2 + 1` = 5 of 9).
- `ParseConsensusSignatures(consensus []byte) ([]ConsensusSignature, error)`.
- `ConsensusSignedDigest(consensus []byte) ([]byte, error)` — the SHA-1 digest
  the signatures cover.
- `VerifyConsensusSignatures(consensus []byte, certs map[string]*AuthorityCert) (int, error)`.
- `ParseAuthorityCert(text []byte) (*AuthorityCert, error)`.

**Notes:** `VerifySignatures` is off by default (for tests that mint their own
consensus) but should be enabled for any real-network use; when on, `Fetch`
downloads the referenced authority certs and rejects the consensus unless the
quorum is met. `UseFallbacks` is the C client's primary bootstrap path.

## circuit

**Purpose:** origin circuits — the client-side abstraction for a multi-hop path
through the Tor network. Built hop by hop with ntor (CREATE2/CREATED2 for the
first hop, EXTEND2/EXTENDED2 for subsequent hops) or CREATE_FAST (one-hop
directory circuits), and carries relay cells (BEGIN/DATA/CONNECTED/END) that
open application streams through the exit.

**Mirrors:** `src/core/or/circuitbuild.c`, `circuitlist.c`, `relay.c`,
`crypt_path_st.h`.

**Key API:**

- `HopState` (`HopStateClosed`, …) and `Hop` — one hop of a circuit: `Relay link.RouterIdentity`,
  `State HopState`, `Crypto *relaycrypto.Layer` (and ntor/fast handshake state).
- `Circuit` — an origin circuit.
  - `New(ctx, l *link.Link, path []link.RouterIdentity) (*Circuit, error)` —
    build a multi-hop circuit (ntor v1/v3, EXTEND2).
  - `NewOneHopFast(ctx, l *link.Link) (*Circuit, error)` — build a one-hop
    CREATE_FAST circuit (for directory bootstrap).
  - `OpenStream(ctx, target string) (*Stream, error)` — RELAY BEGIN a stream to
    `target` (host:port), with IPv6 flags set appropriately.
  - `BeginDir(ctx) (*Stream, error)` — RELAY BEGIN_DIR (directory stream).
  - `Resolve(ctx, hostname string) (string, error)` — RELAY RESOLVE.
  - `Close() error`, `CircID() uint32`, `HopCount() int`.
- `Stream` — an application stream: `ID uint16`, `BoundAddr string` (parsed from
  RELAY_CONNECTED).
  - `Write(p []byte) (int, error)`, `Read() ([]byte, error)`, `Close() error`.
- Errors: `ErrEOF` (normal RELAY_END), `ErrConnRefused`, `ErrHostUnreachable`,
  `ErrNetUnreachable`, `ErrTTLExpired`.
- Constants: `CIRCWINDOW_START = 1000`, `CIRCWINDOW_INCREMENT = 100`,
  `STREAMWINDOW_START = 500`, `MaxRelayEarlyCellsPerCircuit = 8`.

**Notes:** Flow control uses circuit- and stream-level windows with SENDME
refill at the thresholds, and a `RELAY_EARLY` cap of 8 per circuit. END reasons
are mapped to the exported errors (and onward to SOCKS5 replies by the socks5
layer). `Stream.Close` sends END reason 6 (DONE), not 0 (reserved/invalid).

## socks5

**Purpose:** a SOCKS5 (RFC 1928) proxy server that routes CONNECT/RESOLVE/
RESOLVE_PTR requests through Tor circuits provided by a `Dialer`. The
client-facing entry point applications configure their SOCKS5 proxy to.

**Mirrors:** `src/core/proto/proto_socks.c`.

**Key API:**

- `Dialer` — the interface the server routes through: `DialStream(ctx, target) (io.ReadWriteCloser, error)`,
  `Resolve(ctx, hostname) (string, error)`, `ResolvePtr(ctx, ip) (string, error)`.
- `AuthConfig` — `Username`, `Password` (RFC 1929 userpass).
- `Server` — the SOCKS5 server.
  - `New(addr string, dialer Dialer) *Server` — no-auth.
  - `NewWithAuth(addr string, dialer Dialer, auth AuthConfig) *Server` —
    username/password auth.
  - `ListenAndServe() error`, `Addr() net.Addr`, `Shutdown() error`.
  - `RejectPrivateAddresses bool` — when set, refuse CONNECT/RESOLVE/RESOLVE_PTR
    targets that are private, loopback, or link-local (and `localhost`/`*.local`),
    mirroring the C client's `ClientRejectInternalAddresses`. Off by default;
    the real client enables it via `torclient.Config.AllowPrivateAddresses`.

**Notes:** `.onion` targets are refused with "command not supported" (full
hidden-service support is out of scope). END-reason errors from the circuit
layer are mapped to the appropriate SOCKS5 reply code.

## torclient

**Purpose:** the top-level Tor client. Owns the directory, the guard link, the
SOCKS5 listener, and a per-stream circuit builder (a fresh circuit per stream,
for strong isolation). Wires the layers together.

**Mirrors:** composition layer; no single C file.

**Key API:**

- `Config` — programmatic configuration:
  - `SocksAddr string` (library default `127.0.0.1:7890`; the `cmd/tor-go` CLI
    overrides to `127.0.0.1:1080` via `-socks`).
  - `PathLen int` (default 3: guard/middle/exit).
  - `Guard *directory.Router` (pinned guard; bypasses the guard manager).
  - `Directory map[string]*directory.Router` (required).
  - `UpstreamProxy string` (SOCKS5 proxy the link layer dials through).
  - `LinkDialTimeout`, `CircuitBuildTimeout`, `RefreshInterval time.Duration`.
  - `FetchOptions *directory.FetchOptions` (configures background refresh /
    `RefreshDirectory`).
  - `AllowPrivateAddresses bool` (default false = reject private targets).
- `Client` — a running client.
  - `New(ctx, cfg) (*Client, error)` — build the client (select/confirm a guard,
    apply defaults).
  - `Connect(ctx) error` — establish the guard link.
  - `Serve(ctx) error` — block, serving SOCKS5 (and the background refresh loop
    when `RefreshInterval` > 0).
  - `RefreshDirectory(ctx) error` — re-fetch the consensus and swap it in
    race-safely.
  - `Guard() *directory.Router`, `SocksAddr() string`.

**Notes:** `7890` is the upstream proxy tor-go dials *through*; `1080` is
tor-go's own SOCKS5 listener. The per-stream circuit builder means each SOCKS5
connection gets its own circuit (a production client would pool circuits; this
trades efficiency for isolation and simplicity).

## testharness

**Purpose:** an in-process mock Tor relay server for integration and e2e tests.
A `MockRelay` speaks enough of the Tor link and circuit protocols — TLS link
handshake, CREATE2/CREATED2 (ntor), CREATE_FAST/CREATED_FAST, EXTEND2/EXTENDED2,
and RELAY BEGIN/DATA/CONNECTED/END — that the real client packages can build
multi-hop circuits through a chain of mock relays and open streams the exit
relays to a real (loopback) TCP target.

**Mirrors:** test-only; no C mirror (it is a faithful reimplementation of the
server side of the protocols the client packages implement).

**Key API:**

- `RelayConfig` — mock relay configuration (TLS cert, onion keys, identity).
- `MockRelay` — one mock relay.
  - `NewMockRelay(cfg RelayConfig) (*MockRelay, error)`.
- `Harness` — a chain of `n` mock relays (guard, middle, …, exit) on ephemeral
  loopback ports, with generated TLS certs and onion keys, plus a directory the
  client can use.
  - `NewHarness(n int) (*Harness, error)`.
  - `Relays []*MockRelay`, `Close() error`.

**Notes:** The mock is not a toy: it performs the real ntor server handshake,
real CREATE_FAST server handshake, real tor1 relay crypto (reversed layers),
and real multi-hop extension. e2e tests therefore exercise the same client code
paths a real guard/exit would. `TestOneHopFastCircuit` uses a 1-relay harness to
verify the CREATE_FAST one-hop path; `TestLinkHandshake` (in `integration_test.go`)
and the e2e tests in `e2e_test.go` use multi-relay harnesses with
`AllowPrivateAddresses: true` (the mock exit targets a loopback origin). The
real-network e2e (`e2e_real_test.go`, build tag `tor_real`) is separate and
usually skipped.

## cmd/tor-go

**Purpose:** the standalone Tor client command — a thin wrapper that builds a
`torclient.Config` and calls `Serve`.

**Flags:** `-consensus`, `-microdescriptors` (file-based directory), `-socks`
(default `127.0.0.1:1080`), `-pathlen` (default 3), `-mock-dir` (built-in mock
directory), `-upstream` (SOCKS5 dial-through), `-fetch-dir` (bootstrap a real
directory over the network). Exactly one directory source must be chosen:
`-fetch-dir`, `-mock-dir`, or the `-consensus` + `-microdescriptors` pair.

## plugins/tor

**Purpose:** the goose proxy-pool engine's `tor` provider plugin. It embeds
the client packages as a library, bootstraps a real Tor client (directory
fetch, guard link, SOCKS5 listener) in a background goroutine with
exponential-backoff retries, and contributes one `socks5` outbound at the
client's loopback listener once it is serving; `Watch()` signals the
readiness flip so the engine repolls promptly. The consensus is re-fetched
hourly while serving. It lives inside this module (not a separate repo)
because it embeds `internal/torclient` and `internal/directory`; on the goose
side it imports only `goose-plugin-api`, preserving the plugin import
boundary.

**Mirrors:** none (plugin adapter).

**Exported API:** `New(map[string]any) (plugin.Provider, error)` — registered
as `"tor"` via `plugin.RegisterProvider` in `init()`.

**Config keys:** `upstream_proxy`, `path_len`, `socks_listen` (default
ephemeral), `outbound_id` (default `"tor"`), `fetch_timeout_seconds`
(default 300), `max_microdescs`, `verify_signatures` (default **true** — the
quorum is the only consensus authentication, since dirports are plain HTTP),
`use_fallbacks` (incompatible with `verify_signatures`),
`link_dial_timeout_seconds`, `circuit_build_timeout_seconds`,
`allow_private_addresses`. See `plugins/tor/README.md` for the full table
and a goose config example.
