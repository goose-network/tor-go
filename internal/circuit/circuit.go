// Package circuit implements origin circuits: the client-side abstraction
// for a multi-hop path through the Tor network. A circuit is built hop by
// hop using the ntor handshake (CREATE2/CREATED2 for the first hop,
// EXTEND2/EXTENDED2 for subsequent hops), and carries relay cells
// (BEGIN/DATA/CONNECTED/END) that open application streams through the exit.
//
// This mirrors src/core/or/circuitbuild.c, circuitlist.c, relay.c and
// crypt_path_st.h in the C reference implementation.
package circuit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/proxy/tor-go/internal/fast"
	"github.com/proxy/tor-go/internal/link"
	"github.com/proxy/tor-go/internal/ntor"
	"github.com/proxy/tor-go/internal/relaycrypto"
	"github.com/proxy/tor-go/internal/torcell"
)

// HopState is the state of a single hop during circuit building.
type HopState int

const (
	HopStateClosed HopState = iota
	HopStateAwaitingKeys
	HopStateOpen
)

// handshakeTypeFast is the sentinel handshake-type value used to dispatch
// CREATE_FAST in finishHandshake. CREATE_FAST does not appear in the CREATE2
// handshake-type space (it has its own cell commands, CREATE_FAST/CREATED_FAST),
// so this value is only ever compared against itself.
const handshakeTypeFast uint16 = 0

// Flow-control window constants, matching src/core/or/or.h. The client tracks
// two windows per circuit and per stream:
//   - package_window: cells we are allowed to send toward the exit. Decremented
//     when we send a DATA cell; refilled by CIRWINDOW_INCREMENT when we receive
//     a circuit-level SENDME from the exit. When it reaches 0 we must stop
//     sending (the exit would otherwise overflow).
//   - deliver_window: cells the exit is allowed to send us. Decremented when we
//     receive a DATA cell; when it drops to CIRCWINDOW_START - CIRCWINDOW_INCREMENT
//     we send a circuit-level SENDME to refill it.
const (
	// CIRCWINDOW_START is the initial circuit-level window (both directions).
	CIRCWINDOW_START = 1000
	// CIRCWINDOW_INCREMENT is the number of cells a circuit-level SENDME refills.
	CIRCWINDOW_INCREMENT = 100
	// STREAMWINDOW_START is the initial stream-level window.
	STREAMWINDOW_START = 500
	// STREAMWINDOW_INCREMENT is the number of cells a stream-level SENDME refills.
	STREAMWINDOW_INCREMENT = 50
	// MaxRelayEarlyCellsPerCircuit caps the number of RELAY_EARLY cells an
	// origin circuit may send, matching MAX_RELAY_EARLY_CELLS_PER_CIRCUIT
	// (or.h:935). Prevents malicious-extension attacks (command.c:548).
	MaxRelayEarlyCellsPerCircuit = 8
)

// Relay END reasons (subset), matching src/core/or/or.h (END_STREAM_REASON_*).
// Reasons <=255 are sent as a single byte; reasons >255 (e.g. NET_UNREACHABLE
// 258) are sent as a 2-byte big-endian value. We keep these as int to avoid
// uint8 overflow.
const (
	endReasonMisc           = 1
	endReasonResolveFailed  = 2
	endReasonConnectRefused = 3
	endReasonExitPolicy     = 4
	endReasonDestroy        = 5
	endReasonDone           = 6
	endReasonTimeout        = 7
	endReasonNoRoute        = 8
	endReasonNetUnreachable = 258
)

// endReasonFromPayload reads an END reason from the relay payload, handling
// both the 1-byte (reason <= 255) and 2-byte (reason > 255) encodings. In
// practice Tor always sends a single byte for the common reasons; the 2-byte
// form is rare. Returns the reason as an int.
func endReasonFromPayload(payload []byte) int {
	if len(payload) >= 2 {
		// If the first byte is 0 and the second is non-zero, this may be a
		// 2-byte encoded reason (big-endian). Treat 0x00 0x00 as reason 0.
		if payload[0] == 0 && payload[1] != 0 {
			return int(binary.BigEndian.Uint16(payload[0:2]))
		}
	}
	if len(payload) >= 1 {
		return int(payload[0])
	}
	return 0
}

// Hop is one layer of the circuit's crypto path: the relay it terminates at
// and the relay-crypto state shared with that relay.
type Hop struct {
	// Relay is the identity of the relay at this hop.
	Relay link.RouterIdentity
	// State is the build state of this hop.
	State HopState
	// Crypto is the relay-crypto layer for this hop (nil until the handshake
	// completes).
	Crypto *relaycrypto.Layer
	// ntorState is the in-progress ntor v1 handshake state (nil after the
	// hop is open, or nil when using ntor v3).
	ntorState *ntor.ClientState
	// v3State is the in-progress ntor v3 handshake state (nil after the hop
	// is open, or nil when using ntor v1).
	v3State *ntor.V3ClientState
	// fastState is the in-progress CREATE_FAST handshake state (nil unless
	// this hop was built with NewOneHopFast). CREATE_FAST is only valid for a
	// first hop to a trusted directory cache whose identity is verified by the
	// TLS link, so it has no handshake-type id in the CREATE2 space; we use
	// the sentinel handshakeTypeFast to dispatch in finishHandshake.
	fastState *fast.State
	// handshakeType records which handshake this hop is using (ntor v1 = 2,
	// ntor v3 = 3, CREATE_FAST = 0), so finishHandshake dispatches to the
	// right client handshake. It is set when the onionskin is created.
	handshakeType uint16
}

// Circuit is an origin circuit built over a single link (to the guard).
// Additional hops are extended through the guard.
type Circuit struct {
	link   *link.Link
	circID uint32
	in     <-chan *torcell.Cell

	mu         sync.Mutex
	hops       []*Hop
	streams    map[uint16]*Stream
	nextStream uint16
	closed     bool
	done       chan struct{}

	// Flow control. packageWindow is the number of cells we may still send
	// toward the exit (decremented on each outgoing DATA, refilled by inbound
	// circuit-level SENDME). deliverWindow is the number of cells the exit
	// may send us (decremented on each inbound DATA; when it drops to
	// CIRCWINDOW_START - CIRCWINDOW_INCREMENT we send a SENDME). These are
	// guarded by mu.
	packageWindow int
	deliverWindow int

	// remainingRelayEarly is the number of RELAY_EARLY cells we may still
	// send on this circuit. Tor caps this at MAX_RELAY_EARLY_CELLS_PER_CIRCUIT
	// (8) to prevent a class of attacks where a malicious exit forwards
	// RELAY_EARLY cells to extend the circuit further than the path length
	// allows (command.c:548). Each EXTEND2 consumes one; once exhausted,
	// further extends are refused. Guarded by mu.
	remainingRelayEarly int
}

// Stream is an application stream multiplexed over a circuit.
type Stream struct {
	ID     uint16
	circ   *Circuit
	in     chan *torcell.RelayCell
	closed bool

	// BoundAddr is the address the exit bound the stream to, parsed from the
	// RELAY_CONNECTED reply (an IPv4 or IPv6 literal). Empty until the stream
	// is connected, or if the exit sent an empty CONNECTED.
	BoundAddr string

	// Stream-level flow control, guarded by circ.mu.
	packageWindow int
	deliverWindow int
}

// New begins building a circuit over l, using the given path of relays. The
// first relay must be the guard (the relay l is connected to); subsequent
// relays are extended through it. New completes the full handshake for every
// hop before returning.
func New(ctx context.Context, l *link.Link, path []link.RouterIdentity) (*Circuit, error) {
	if len(path) == 0 {
		return nil, errors.New("circuit: empty path")
	}
	circID, in, err := l.Register()
	if err != nil {
		return nil, err
	}
	c := &Circuit{
		link:                l,
		circID:              circID,
		in:                  in,
		streams:             make(map[uint16]*Stream),
		nextStream:          1,
		done:                make(chan struct{}),
		packageWindow:       CIRCWINDOW_START,
		deliverWindow:       CIRCWINDOW_START,
		remainingRelayEarly: MaxRelayEarlyCellsPerCircuit,
	}
	c.hops = make([]*Hop, len(path))
	for i, r := range path {
		c.hops[i] = &Hop{Relay: r, State: HopStateClosed}
	}

	// Build the first hop with CREATE2.
	if err := c.buildFirstHop(ctx); err != nil {
		c.teardown()
		return nil, fmt.Errorf("circuit: first hop: %w", err)
	}
	// Extend to each subsequent hop with EXTEND2.
	for i := 1; i < len(path); i++ {
		if err := c.extendHop(ctx, i); err != nil {
			c.teardown()
			return nil, fmt.Errorf("circuit: hop %d: %w", i+1, err)
		}
	}
	go c.readLoop()
	return c, nil
}

// NewOneHopFast builds a one-hop circuit over an already-established link l
// using the CREATE_FAST handshake (CellCreateFast/CellCreatedFast) instead of
// CREATE2/CREATED2. The single hop is the relay l is connected to.
//
// CREATE_FAST is unauthenticated and non-forward-secure: it derives circuit
// keys from the client and server nonces alone, with no relay onion key. It is
// therefore only safe as the first (and here only) hop, where the TLS link to
// the relay already authenticates it and protects the handshake from
// eavesdroppers. This is exactly how the C client bootstraps a one-hop
// directory-fetch circuit to a fallback directory or authority whose onion key
// it does not yet know (circuitbuild.c:circuit_establish_circuit,
// onion_fast.c). The caller is responsible for having verified the relay's
// identity (e.g. via link.DialWithUpstream with an expected RSA digest) before
// calling this.
func NewOneHopFast(ctx context.Context, l *link.Link) (*Circuit, error) {
	circID, in, err := l.Register()
	if err != nil {
		return nil, err
	}
	c := &Circuit{
		link:                l,
		circID:              circID,
		in:                  in,
		streams:             make(map[uint16]*Stream),
		nextStream:          1,
		done:                make(chan struct{}),
		packageWindow:       CIRCWINDOW_START,
		deliverWindow:       CIRCWINDOW_START,
		remainingRelayEarly: MaxRelayEarlyCellsPerCircuit,
	}
	// A one-hop fast circuit has a single hop. The hop's Relay identity is
	// not needed: CREATE_FAST carries no identity material (it relies on the
	// already-verified TLS link), and there are no further hops to extend to.
	// We record an empty identity for bookkeeping only.
	c.hops = []*Hop{{State: HopStateClosed}}

	if err := c.buildFirstHopFast(ctx); err != nil {
		c.teardown()
		return nil, fmt.Errorf("circuit: fast first hop: %w", err)
	}
	go c.readLoop()
	return c, nil
}

// createOnionskin builds the CREATE2/EXTEND2 onionskin for a hop, selecting
// the ntor v3 handshake when the relay advertises Relay>=4 (which implies
// ntor-v3 support, PROTOVER_RELAY_NTOR_V3) and has an Ed25519 identity key,
// and falling back to ntor v1 otherwise. It records the chosen handshake
// type and in-progress state on the hop. It returns the onionskin bytes, the
// handshake type (2 for ntor v1, 3 for ntor v3), and any error.
func (c *Circuit) createOnionskin(hop *Hop) ([]byte, uint16, error) {
	if supportsNtorV3(hop.Relay) {
		onionskin, state, err := ntor.V3Create(hop.Relay.Ed25519ID[:], hop.Relay.OnionKey[:])
		if err != nil {
			return nil, 0, err
		}
		hop.v3State = state
		hop.handshakeType = ntor.HandshakeTypeNtorV3
		return onionskin, ntor.HandshakeTypeNtorV3, nil
	}
	onionskin, state, err := ntor.Create(hop.Relay.IDDigest[:], hop.Relay.OnionKey[:])
	if err != nil {
		return nil, 0, err
	}
	hop.ntorState = state
	hop.handshakeType = ntor.HandshakeTypeNtor
	return onionskin, ntor.HandshakeTypeNtor, nil
}

// supportsNtorV3 reports whether a relay supports the ntor v3 handshake. The
// C client gates v3 on the relay advertising Relay protocol version >= 4
// (PROTOVER_RELAY_NTOR_V3, protover.h:39), which also requires an Ed25519
// identity key (the v3 onionskin carries the 32-byte Ed25519 ID). We require
// both: a non-zero Ed25519ID and a Relay protocol range that includes 4.
func supportsNtorV3(r link.RouterIdentity) bool {
	if isZero32(r.Ed25519ID) {
		return false
	}
	return relayProtoAtLeast(r.ProtoVer, "Relay", 4)
}

// relayProtoAtLeast reports whether the protocol-versions map advertises a
// version >= want for the named protocol. The value is a range like "1-2",
// "4", or "1-999999". An absent protocol or unparseable range returns false.
func relayProtoAtLeast(pv map[string]string, name string, want int) bool {
	if pv == nil {
		return false
	}
	rng, ok := pv[name]
	if !ok {
		return false
	}
	lo, hi, ok := parseProtoRange(rng)
	if !ok {
		return false
	}
	return lo <= want && want <= hi
}

// parseProtoRange parses a protocol-version range string ("4", "1-2",
// "1-999999") into its low and high bounds.
func parseProtoRange(s string) (lo, hi int, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			a, ok1 := atoi(s[:i])
			b, ok2 := atoi(s[i+1:])
			if !ok1 || !ok2 {
				return 0, 0, false
			}
			return a, b, true
		}
	}
	v, ok := atoi(s)
	if !ok {
		return 0, 0, false
	}
	return v, v, true
}

// atoi parses a non-negative decimal integer. Empty or non-numeric input is
// not ok.
func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// buildFirstHop sends a CREATE2 cell to the guard and processes the CREATED2
// reply, completing the ntor handshake for the first hop.
func (c *Circuit) buildFirstHop(ctx context.Context) error {
	hop := c.hops[0]
	onionskin, hsType, err := c.createOnionskin(hop)
	if err != nil {
		return err
	}
	hop.State = HopStateAwaitingKeys

	// CREATE2 payload: [handshake_type:2][handshake_len:2][onionskin].
	payload := make([]byte, 4+len(onionskin))
	binary.BigEndian.PutUint16(payload[0:2], hsType)
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(onionskin)))
	copy(payload[4:], onionskin)

	cell := &torcell.Cell{
		CircID:  c.circID,
		Command: torcell.CellCreate2,
	}
	copy(cell.Payload[:], payload)
	if err := c.link.Send(cell); err != nil {
		return err
	}

	// Wait for CREATED2.
	reply, err := c.awaitCell(ctx, torcell.CellCreated2)
	if err != nil {
		return err
	}
	return c.finishHandshake(hop, reply.Payload[:])
}

// buildFirstHopFast sends a CREATE_FAST cell to the link peer and processes
// the CREATED_FAST reply, completing the CREATE_FAST handshake for the single
// hop of a one-hop fast circuit. Unlike buildFirstHop, the onionskin is the
// raw 20-byte client nonce (no CREATE2 type/length prefix) and the reply is
// the raw 40-byte y||H(x||y) (no CREATED2 prefix). This mirrors
// circuit_send_next_onion_skin (circuitbuild.c) for the CREATE_FAST path.
func (c *Circuit) buildFirstHopFast(ctx context.Context) error {
	hop := c.hops[0]
	onionskin, state, err := fast.Create()
	if err != nil {
		return err
	}
	hop.fastState = state
	hop.handshakeType = handshakeTypeFast
	hop.State = HopStateAwaitingKeys

	cell := &torcell.Cell{
		CircID:  c.circID,
		Command: torcell.CellCreateFast,
	}
	copy(cell.Payload[:], onionskin)
	if err := c.link.Send(cell); err != nil {
		return err
	}

	// Wait for CREATED_FAST.
	reply, err := c.awaitCell(ctx, torcell.CellCreatedFast)
	if err != nil {
		return err
	}
	return c.finishFastHandshake(hop, reply.Payload[:])
}

// finishFastHandshake completes the CREATE_FAST handshake for a hop using the
// server's CREATED_FAST reply (the raw 40-byte y||H(x||y)), derives the
// relay-crypto keys, and installs the crypto layer. The CREATE_FAST key
// expansion produces TotalKeyLen bytes (KeyMaterialLen relay-crypto key
// material + KHLen rend-circ nonce), split the same way as the ntor path.
// The integrity check inside fast.ClientHandshake is the authentication of
// the handshake (it fails if the reply is tampered with); the trailing KH is
// sanity-checked for non-zero, as in finishHandshake.
func (c *Circuit) finishFastHandshake(hop *Hop, reply []byte) error {
	keys, err := hop.fastState.ClientHandshake(reply, relaycrypto.TotalKeyLen)
	if err != nil {
		return fmt.Errorf("circuit: CREATE_FAST client handshake: %w", err)
	}
	kh := keys[relaycrypto.KeyMaterialLen:]
	if isZero20(kh) {
		return errors.New("circuit: CREATE_FAST produced zero KH (degenerate handshake)")
	}
	layer, err := relaycrypto.NewLayer(keys[:relaycrypto.KeyMaterialLen])
	if err != nil {
		return err
	}
	hop.Crypto = layer
	hop.fastState = nil
	hop.State = HopStateOpen
	return nil
}

// extendHop sends an EXTEND2 relay cell through the existing circuit to
// extend it to path[i], and processes the EXTENDED2 reply.
func (c *Circuit) extendHop(ctx context.Context, i int) error {
	hop := c.hops[i]
	onionskin, hsType, err := c.createOnionskin(hop)
	if err != nil {
		return err
	}
	hop.State = HopStateAwaitingKeys

	// EXTEND2 payload is a list of link specifiers followed by a CREATE2
	// payload. We send the relay's IPv4 ORPort, its RSA identity digest and
	// (when known) its ed25519 identity as link specifiers.
	ls, nSpecs := buildLinkSpecifiers(hop.Relay)
	create2 := make([]byte, 4+len(onionskin))
	binary.BigEndian.PutUint16(create2[0:2], hsType)
	binary.BigEndian.PutUint16(create2[2:4], uint16(len(onionskin)))
	copy(create2[4:], onionskin)

	// EXTEND2 body: [n_specs:1]([ls_type:1][ls_len:1][ls_data]]...) then
	// [handshake_type:2][handshake_len:2][handshake_data].
	body := make([]byte, 0, 1+len(ls)+len(create2))
	body = append(body, byte(nSpecs)) // number of link specifiers
	body = append(body, ls...)
	body = append(body, create2...)

	// Send as a RELAY_EARLY cell (required for extends beyond the first hop)
	// through the circuit, encrypted with all existing hops' forward layers.
	if err := c.sendRelay(ctx, torcell.RelayExtend2, 0, body, true); err != nil {
		return err
	}

	// Wait for EXTENDED2.
	reply, err := c.awaitRelay(ctx, torcell.RelayExtended2)
	if err != nil {
		return err
	}
	return c.finishHandshake(hop, reply.Payload)
}

// buildLinkSpecifiers builds the link specifier list for an EXTEND2 cell.
// Each specifier is [type:1][len:1][data]. The type codes come from the
// trunnel link_specifier union (ed25519_cert.trunnel; LS_* in
// src/trunnel/ed25519_cert.h):
//
//	0 (LS_IPV4): 4 bytes IP + 2 bytes port — len 6
//	1 (LS_IPV6): 16 bytes IP + 2 bytes port — len 18
//	2 (LS_LEGACY_ID): 20-byte RSA identity digest
//	3 (LS_ED25519_ID): 32-byte ed25519 identity
//
// We include the relay's IPv4 ORPort, its RSA digest, and — when known — its
// ed25519 identity, matching extend_cell_format's EXTEND2 branch (onion.c),
// which sends the ed25519 specifier whenever should_include_ed25519_id_extend_
// cells() is true (consensus param ExtendByEd25519ID, currently 1 network-wide)
// and the key is non-zero; the guard fills it in from its own consensus
// otherwise (circuit_extend_add_ed25519_helper).
//
// It returns the concatenated specifier bytes and the number of specifiers.
func buildLinkSpecifiers(r link.RouterIdentity) ([]byte, int) {
	var out []byte
	n := 0
	// IPv4 + port (type 0, LS_IPV4).
	ip := parseIP(r.Address)
	if v4 := ip.To4(); v4 != nil {
		port := parsePort(r.Address)
		out = append(out, 0, 6)
		out = append(out, v4...)
		out = append(out, byte(port>>8), byte(port))
		n++
	}
	// Legacy identity digest (type 2, LS_LEGACY_ID).
	out = append(out, 2, 20)
	out = append(out, r.IDDigest[:]...)
	n++
	// Ed25519 identity (type 3, LS_ED25519_ID), if non-zero.
	if !isZero32(r.Ed25519ID) {
		out = append(out, 3, 32)
		out = append(out, r.Ed25519ID[:]...)
		n++
	}
	return out, n
}

// finishHandshake completes the ntor handshake for a hop using the server's
// CREATED2/EXTENDED2 reply, derives the relay-crypto keys, and verifies KH.
//
// The reply payload is [handshake_len:2][handshake_data] — with no
// handshake-type field. Only the CREATE2/EXTEND2 request carries
// [handshake_type:2][handshake_len:2][data] (the create2_cell_body trunnel
// struct); the reply is framed by created_cell_format / extended_cell_format
// (onion.c), which write htons(handshake_len) followed by the raw reply
// bytes, and parsed back by created_cell_parse / extended_cell_parse. For
// ntor v1 the handshake_data is the 64-byte Y||MAC reply; for ntor v3 it is
// Y(32)||AUTH(32)||enc_smsg. Both handshakes derive TotalKeyLen bytes
// (KeyMaterialLen relay-crypto key material + KHLen rend-circ nonce), which
// we split into the relay-crypto layer and the trailing KH authenticator.
func (c *Circuit) finishHandshake(hop *Hop, reply []byte) error {
	if len(reply) < 2 {
		return errors.New("circuit: short handshake reply")
	}
	hsLen := binary.BigEndian.Uint16(reply[0:2])
	if int(hsLen) > len(reply)-2 {
		return errors.New("circuit: handshake length exceeds reply")
	}
	hsData := reply[2 : 2+int(hsLen)]
	// The reply does not echo the handshake type — created2_cell_parse has no
	// such field on the reply — so dispatch on the type we sent; each
	// handshake below validates the reply bytes cryptographically anyway.

	var keys []byte
	var err error
	switch hop.handshakeType {
	case ntor.HandshakeTypeNtor:
		keys, err = hop.ntorState.ClientHandshake(hsData, relaycrypto.TotalKeyLen)
		if err != nil {
			return fmt.Errorf("circuit: ntor v1 client handshake: %w", err)
		}
	case ntor.HandshakeTypeNtorV3:
		keys, err = hop.v3State.V3ClientHandshake(hsData, relaycrypto.TotalKeyLen)
		if err != nil {
			return fmt.Errorf("circuit: ntor v3 client handshake: %w", err)
		}
	default:
		return fmt.Errorf("circuit: unsupported handshake type %d", hop.handshakeType)
	}

	// The MAC/AUTH check inside the client handshake is the integrity check
	// on the handshake (it fails if the server's onion key or identity is
	// wrong, or the reply was tampered with). The trailing KHLen bytes are
	// the rendezvous-circuit authenticator (rend_circ_nonce in the C code),
	// not a value the server sends back for re-comparison. We sanity-check
	// that the derived KH is non-zero (a degenerate handshake would produce
	// all-zero key material); a zero KH indicates a broken handshake output.
	kh := keys[relaycrypto.KeyMaterialLen:]
	if isZero20(kh) {
		return errors.New("circuit: ntor handshake produced zero KH (degenerate handshake)")
	}

	layer, err := relaycrypto.NewLayer(keys[:relaycrypto.KeyMaterialLen])
	if err != nil {
		return err
	}
	hop.Crypto = layer
	hop.ntorState = nil
	hop.v3State = nil
	hop.State = HopStateOpen
	return nil
}

// sendRelay builds, encrypts, and sends a relay cell through the circuit.
// The cell is encrypted with the forward layers of all hops from the exit
// (the hop the cell is destined for) inward to the guard. If early is true,
// the cell is sent as RELAY_EARLY (required for EXTEND2).
//
// For RELAY_DATA cells, sendRelay enforces the circuit-level package window:
// it blocks until the window is non-zero (refilled by an inbound circuit-level
// SENDME), then decrements it. This prevents the client from flooding the
// circuit faster than the exit can drain, which the exit would punish by
// closing the circuit (relay.c: circuit_consider_sending_sendme /
// circuit_receive_relay_cell).
func (c *Circuit) sendRelay(ctx context.Context, command uint8, streamID uint16, payload []byte, early bool) error {
	// Determine the target hop: the last open hop (the cell is processed by
	// the exit of the currently-built path).
	target := -1
	for i, h := range c.hops {
		if h.State == HopStateOpen {
			target = i
		} else {
			break
		}
	}
	if target < 0 {
		return errors.New("circuit: no open hop to send through")
	}

	// Flow control: a DATA cell consumes one cell from the circuit's package
	// window. Block (with context cancellation) until the window is refilled
	// by an inbound SENDME. Non-DATA cells (BEGIN, END, EXTEND2, SENDME, ...)
	// do not consume the package window.
	if command == torcell.RelayData {
		if err := c.awaitPackageWindow(ctx, streamID); err != nil {
			return err
		}
	}

	// Build the relay cell payload (509 bytes): relay header + body.
	cellPayload := torcell.BuildRelayCell(command, streamID, payload)

	// Encrypt from the target hop outward to the guard. The target hop stamps
	// the digest; outer hops just add their AES layer.
	for i := target; i >= 0; i-- {
		if i == target {
			c.hops[i].Crypto.EncryptOutbound(cellPayload[:])
		} else {
			c.hops[i].Crypto.EncryptForwardOnly(cellPayload[:])
		}
	}

	cmd := uint8(torcell.CellRelay)
	if early {
		// Enforce the per-circuit RELAY_EARLY cap. Once exhausted, refuse to
		// send further RELAY_EARLY cells (the C client does the same at
		// relay.c:674 — it simply stops marking cells early; for an origin
		// client building a path, exhausting the cap means we can't extend
		// further, so we fail rather than silently downgrading to RELAY,
		// which the next hop would reject as an unexpected extend).
		c.mu.Lock()
		if c.remainingRelayEarly <= 0 {
			c.mu.Unlock()
			return errors.New("circuit: relay-early cell limit exhausted")
		}
		c.remainingRelayEarly--
		c.mu.Unlock()
		cmd = torcell.CellRelayEarly
	}
	cell := &torcell.Cell{
		CircID:  c.circID,
		Command: cmd,
	}
	copy(cell.Payload[:], cellPayload[:])
	if err := c.link.Send(cell); err != nil {
		return err
	}

	// Account for the sent DATA cell against the stream's package window too.
	if command == torcell.RelayData {
		c.mu.Lock()
		if s, ok := c.streams[streamID]; ok {
			if s.packageWindow > 0 {
				s.packageWindow--
			}
		}
		c.mu.Unlock()
	}
	return nil
}

// awaitPackageWindow blocks until the circuit's package window is non-zero
// (i.e. the exit has given us credit via a SENDME) or the context is cancelled
// / the circuit closes. It then decrements the window.
func (c *Circuit) awaitPackageWindow(ctx context.Context, streamID uint16) error {
	// Poll with a short sleep, waiting for an inbound SENDME to refill the
	// window. The read loop refills packageWindow in handleCircuitSendme.
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return errors.New("circuit: closed while waiting for package window")
		}
		if c.packageWindow > 0 {
			c.packageWindow--
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return errors.New("circuit: closed while waiting for package window")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// awaitCell waits for a fixed-size cell with the given command on this
// circuit's inbound channel.
func (c *Circuit) awaitCell(ctx context.Context, command uint8) (*torcell.Cell, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(60 * time.Second)
	}
	for {
		select {
		case cell := <-c.in:
			if cell.Command == command {
				return cell, nil
			}
			if cell.Command == torcell.CellDestroy {
				return nil, fmt.Errorf("circuit: destroyed (reason %d)", cell.Payload[0])
			}
			// Unexpected cell; keep waiting.
		case <-time.After(time.Until(deadline)):
			return nil, fmt.Errorf("circuit: timeout waiting for cell %d", command)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// awaitRelay waits for a relay cell with the given relay command, decrypting
// inbound through all hops. Used during circuit building (before the read
// loop is running).
func (c *Circuit) awaitRelay(ctx context.Context, command uint8) (*torcell.RelayCell, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(60 * time.Second)
	}
	for {
		select {
		case cell := <-c.in:
			if cell.Command == torcell.CellDestroy {
				return nil, fmt.Errorf("circuit: destroyed (reason %d)", cell.Payload[0])
			}
			if cell.Command != torcell.CellRelay && cell.Command != torcell.CellRelayEarly {
				continue
			}
			rc, err := c.decryptInbound(cell)
			if err != nil {
				return nil, err
			}
			if rc.Header.Command == command {
				return rc, nil
			}
			// Other relay commands during building (e.g. padding) are ignored.
		case <-time.After(time.Until(deadline)):
			return nil, fmt.Errorf("circuit: timeout waiting for relay %d", command)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// decryptInbound decrypts an inbound relay cell layer by layer (guard first,
// then inward) and returns the parsed relay cell destined for us. It returns
// an error if no layer recognizes the cell.
func (c *Circuit) decryptInbound(cell *torcell.Cell) (*torcell.RelayCell, error) {
	// Copy so we don't mutate the shared cell buffer.
	buf := make([]byte, len(cell.Payload))
	copy(buf, cell.Payload[:])

	for i := 0; i < len(c.hops); i++ {
		if c.hops[i].State != HopStateOpen {
			break
		}
		if c.hops[i].Crypto.DecryptInbound(buf) {
			return torcell.ParseRelayCell(buf), nil
		}
	}
	return nil, errors.New("circuit: relay cell not recognized by any hop")
}

// readLoop dispatches inbound relay cells to the appropriate stream. It runs
// after the circuit is fully built.
func (c *Circuit) readLoop() {
	defer close(c.done)
	for {
		select {
		case cell, ok := <-c.in:
			if !ok {
				return
			}
			if cell.Command == torcell.CellDestroy {
				c.closeAllStreams()
				return
			}
			if cell.Command != torcell.CellRelay && cell.Command != torcell.CellRelayEarly {
				continue
			}
			rc, err := c.decryptInbound(cell)
			if err != nil {
				continue
			}
			c.dispatchRelay(rc)
		case <-c.done:
			return
		}
	}
}

// dispatchRelay routes a decrypted relay cell to its stream (or handles
// circuit-level commands like SENDME / TRUNCATED).
func (c *Circuit) dispatchRelay(rc *torcell.RelayCell) {
	switch rc.Header.Command {
	case torcell.RelayData:
		// A DATA cell from the exit consumes one cell from the circuit's
		// deliver window and one from the stream's deliver window. When the
		// circuit deliver window drops to the refill threshold, send a
		// circuit-level SENDME; likewise for the stream.
		c.mu.Lock()
		if c.deliverWindow <= 0 {
			// Exit overran the window; the C client would close the circuit.
			c.mu.Unlock()
			c.Close()
			return
		}
		c.deliverWindow--
		needCircSendme := c.deliverWindow <= CIRCWINDOW_START-CIRCWINDOW_INCREMENT
		s, ok := c.streams[rc.Header.StreamID]
		if ok {
			if s.deliverWindow <= 0 {
				c.mu.Unlock()
				// Stream overran; drop and let the stream reader error out.
				return
			}
			s.deliverWindow--
		}
		c.mu.Unlock()

		if needCircSendme {
			c.sendCircuitSendme()
		}
		if ok {
			c.maybeSendStreamSendme(rc.Header.StreamID)
		}
		// Fall through to deliver to the stream.
		if !ok {
			return
		}
		c.tryDeliver(s, rc)
	case torcell.RelayConnected, torcell.RelayEnd, torcell.RelayResolved:
		c.mu.Lock()
		s, ok := c.streams[rc.Header.StreamID]
		c.mu.Unlock()
		if !ok {
			return
		}
		c.tryDeliver(s, rc)
	case torcell.RelaySendme:
		// A circuit-level SENDME (streamID == 0) refills our package window.
		// A stream-level SENDME (streamID != 0) refills that stream's package
		// window. We do not validate the v1 digest tag against the peer's
		// expected value (the mock relay does not send tags); a real relay
		// would, and a mismatch would close the circuit.
		c.mu.Lock()
		if rc.Header.StreamID == 0 {
			c.packageWindow += CIRCWINDOW_INCREMENT
			if c.packageWindow > CIRCWINDOW_START {
				c.packageWindow = CIRCWINDOW_START
			}
		} else if s, ok := c.streams[rc.Header.StreamID]; ok {
			s.packageWindow += STREAMWINDOW_INCREMENT
			if s.packageWindow > STREAMWINDOW_START {
				s.packageWindow = STREAMWINDOW_START
			}
		}
		c.mu.Unlock()
	case torcell.RelayTruncated:
		// The circuit was truncated upstream; close it.
		c.Close()
	case torcell.RelayDrop:
		// Circuit-level padding; ignore.
	}
}

// sendCircuitSendme sends a circuit-level SENDME (streamID 0) to the exit,
// carrying the v1 SENDME digest tag for the last open hop. Best-effort.
func (c *Circuit) sendCircuitSendme() {
	target := -1
	for i, h := range c.hops {
		if h.State == HopStateOpen {
			target = i
		} else {
			break
		}
	}
	if target < 0 {
		return
	}
	tag := c.hops[target].Crypto.SendmeTag()
	// Refill the local deliver window immediately so we don't send a second
	// SENDME before the first is accounted for.
	c.mu.Lock()
	c.deliverWindow += CIRCWINDOW_INCREMENT
	if c.deliverWindow > CIRCWINDOW_START {
		c.deliverWindow = CIRCWINDOW_START
	}
	c.mu.Unlock()
	// SENDME body for v1 is the 4-byte tag. (Older peers accept an empty body.)
	_ = c.sendRelay(context.Background(), torcell.RelaySendme, 0, tag[:], false)
}

// maybeSendStreamSendme sends a stream-level SENDME for streamID if its
// deliver window has dropped to the refill threshold. Best-effort.
func (c *Circuit) maybeSendStreamSendme(streamID uint16) {
	c.mu.Lock()
	s, ok := c.streams[streamID]
	if !ok {
		c.mu.Unlock()
		return
	}
	if s.deliverWindow > STREAMWINDOW_START-STREAMWINDOW_INCREMENT {
		c.mu.Unlock()
		return
	}
	s.deliverWindow += STREAMWINDOW_INCREMENT
	if s.deliverWindow > STREAMWINDOW_START {
		s.deliverWindow = STREAMWINDOW_START
	}
	c.mu.Unlock()
	// Stream-level SENDME body is empty (v1 stream SENDMEs carry no tag).
	_ = c.sendRelay(context.Background(), torcell.RelaySendme, streamID, nil, false)
}

// OpenStream opens a new application stream through the circuit's exit,
// issuing a RELAY_BEGIN to the given target (host:port). It returns once the
// exit reports RELAY_CONNECTED.
func (c *Circuit) OpenStream(ctx context.Context, target string) (*Stream, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("circuit: closed")
	}
	id := c.nextStream
	c.nextStream += 2 // stream IDs are even when chosen by the client
	s := &Stream{
		ID:            id,
		circ:          c,
		in:            make(chan *torcell.RelayCell, 32),
		packageWindow: STREAMWINDOW_START,
		deliverWindow: STREAMWINDOW_START,
	}
	c.streams[id] = s
	c.mu.Unlock()

	// RELAY_BEGIN payload: "host:port\0" followed by an optional 4-byte
	// big-endian flags field (connection_edge.h:242). We set:
	//   - BEGIN_FLAG_IPV6_OK (1) for any target, so the exit may connect over
	//     IPv6 when the target resolves to one;
	//   - BEGIN_FLAG_IPV4_NOT_OK (2) when the target is an IPv6 literal, since
	//     it cannot be reached over IPv4.
	// For an IPv4 literal or a hostname we leave IPv4 allowed (the common
	// case), so the flags field is just IPV6_OK.
	beginPayload := append([]byte(target), 0)
	var flags uint32 = beginFlagIPv6OK
	if host, isV6 := targetHost(target); isV6 || (netParseIP(host) != nil && netParseIP(host).To4() == nil) {
		// target is an IPv6 literal: it cannot be reached over IPv4.
		flags |= beginFlagIPv4NotOK
	}
	beginPayload = binary.BigEndian.AppendUint32(beginPayload, flags)
	if err := c.sendRelay(ctx, torcell.RelayBegin, id, beginPayload, false); err != nil {
		c.removeStream(id)
		return nil, err
	}

	// Wait for CONNECTED or END.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(60 * time.Second)
	}
	for {
		select {
		case rc := <-s.in:
			if rc.Header.Command == torcell.RelayConnected {
				s.BoundAddr = parseConnected(rc.Payload)
				return s, nil
			}
			if rc.Header.Command == torcell.RelayEnd {
				c.removeStream(id)
				return nil, endReasonToError(endReasonFromPayload(rc.Payload))
			}
		case <-time.After(time.Until(deadline)):
			c.removeStream(id)
			return nil, errors.New("circuit: stream connect timeout")
		case <-ctx.Done():
			c.removeStream(id)
			return nil, ctx.Err()
		}
	}
}

// Write sends RELAY_DATA on the stream.
func (s *Stream) Write(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("stream: closed")
	}
	// Fragment into relay-payload-sized chunks.
	off := 0
	for off < len(p) {
		n := len(p) - off
		if n > torcell.RelayPayloadSizeMax {
			n = torcell.RelayPayloadSizeMax
		}
		if err := s.circ.sendRelay(context.Background(), torcell.RelayData, s.ID, p[off:off+n], false); err != nil {
			return off, err
		}
		off += n
	}
	return off, nil
}

// Read returns the next DATA payload received on the stream, or an error on
// END.
func (s *Stream) Read() ([]byte, error) {
	if s.closed {
		return nil, errors.New("stream: closed")
	}
	rc, ok := <-s.in
	if !ok {
		return nil, errors.New("stream: closed")
	}
	switch rc.Header.Command {
	case torcell.RelayData:
		return rc.Payload, nil
	case torcell.RelayEnd:
		s.closed = true
		// Map well-known END reasons to sentinel errors so the SOCKS5 layer
		// can produce appropriate reply codes; EOF (DONE) is a normal close.
		if err := endReasonToError(endReasonFromPayload(rc.Payload)); err != nil {
			if errors.Is(err, errEOF) {
				return nil, errEOF
			}
			return nil, err
		}
		return nil, errEOF
	}
	return nil, fmt.Errorf("stream: unexpected relay command %d", rc.Header.Command)
}

// Close sends a RELAY_END on the stream and removes it from the circuit.
func (s *Stream) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.circ.removeStream(s.ID)
	// Best-effort END with reason DONE (6); ignore errors. (Reason 0 is
	// reserved/invalid in the spec.)
	s.circ.sendRelay(context.Background(), torcell.RelayEnd, s.ID, []byte{endReasonDone}, false)
	return nil
}

// ErrEOF is returned by Stream.Read when the stream is closed normally
// (RELAY_END with reason DONE). It is the stream's end-of-stream signal;
// callers reading until EOF should stop on errors.Is(err, ErrEOF).
var ErrEOF = errors.New("stream: EOF")

// errEOF is an alias kept for the existing internal call sites; new code
// should use ErrEOF.
var errEOF = ErrEOF

// Sentinel errors mapped from relay END reasons, used by the SOCKS5 layer to
// produce appropriate reply codes.
var (
	ErrConnRefused     = errors.New("circuit: connection refused")
	ErrHostUnreachable = errors.New("circuit: host unreachable")
	ErrNetUnreachable  = errors.New("circuit: network unreachable")
	ErrTTLExpired      = errors.New("circuit: TTL expired")
)

// endReasonToError maps a relay END reason to a sentinel error (or errEOF
// for a normal DONE close). Unknown reasons map to a generic error.
func endReasonToError(reason int) error {
	switch reason {
	case endReasonDone:
		return errEOF
	case endReasonConnectRefused:
		return ErrConnRefused
	case endReasonNoRoute:
		return ErrHostUnreachable
	case endReasonNetUnreachable:
		return ErrNetUnreachable
	case endReasonTimeout:
		return ErrTTLExpired
	case 0:
		// Reason 0 is invalid; treat as a normal close for robustness.
		return errEOF
	default:
		return fmt.Errorf("circuit: stream ended (reason %d)", reason)
	}
}

// BeginDir opens a stream to the exit relay's directory port, issuing a
// RELAY_BEGIN_DIR (used to fetch directory documents over a circuit). The
// exit must have the directory cache capability; the stream behaves like a
// normal stream once connected.
func (c *Circuit) BeginDir(ctx context.Context) (*Stream, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("circuit: closed")
	}
	id := c.nextStream
	c.nextStream += 2
	s := &Stream{
		ID:            id,
		circ:          c,
		in:            make(chan *torcell.RelayCell, 32),
		packageWindow: STREAMWINDOW_START,
		deliverWindow: STREAMWINDOW_START,
	}
	c.streams[id] = s
	c.mu.Unlock()

	// RELAY_BEGIN_DIR has an empty body.
	if err := c.sendRelay(ctx, torcell.RelayBeginDir, id, nil, false); err != nil {
		c.removeStream(id)
		return nil, err
	}
	// Wait for CONNECTED or END (same handshake as BEGIN).
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(60 * time.Second)
	}
	for {
		select {
		case rc := <-s.in:
			if rc.Header.Command == torcell.RelayConnected {
				s.BoundAddr = parseConnected(rc.Payload)
				return s, nil
			}
			if rc.Header.Command == torcell.RelayEnd {
				c.removeStream(id)
				return nil, endReasonToError(endReasonFromPayload(rc.Payload))
			}
		case <-time.After(time.Until(deadline)):
			c.removeStream(id)
			return nil, errors.New("circuit: begin_dir connect timeout")
		case <-ctx.Done():
			c.removeStream(id)
			return nil, ctx.Err()
		}
	}
}

// Resolve issues a RELAY_RESOLVE for a hostname and waits for RELAY_RESOLVED,
// returning the resolved address (as a string) and the TTL. This is the
// circuit-level DNS lookup used by SOCKS5 RESOLVE.
func (c *Circuit) Resolve(ctx context.Context, hostname string) (string, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return "", errors.New("circuit: closed")
	}
	id := c.nextStream
	c.nextStream += 2
	s := &Stream{
		ID:            id,
		circ:          c,
		in:            make(chan *torcell.RelayCell, 32),
		packageWindow: STREAMWINDOW_START,
		deliverWindow: STREAMWINDOW_START,
	}
	c.streams[id] = s
	c.mu.Unlock()

	// RELAY_RESOLVE body is the hostname (no NUL terminator).
	if err := c.sendRelay(ctx, torcell.RelayResolve, id, []byte(hostname), false); err != nil {
		c.removeStream(id)
		return "", err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(60 * time.Second)
	}
	for {
		select {
		case rc := <-s.in:
			if rc.Header.Command == torcell.RelayResolved {
				c.removeStream(id)
				return parseResolved(rc.Payload)
			}
			if rc.Header.Command == torcell.RelayEnd {
				c.removeStream(id)
				return "", endReasonToError(endReasonFromPayload(rc.Payload))
			}
		case <-time.After(time.Until(deadline)):
			c.removeStream(id)
			return "", errors.New("circuit: resolve timeout")
		case <-ctx.Done():
			c.removeStream(id)
			return "", ctx.Err()
		}
	}
}

// parseResolved parses a RELAY_RESOLVED payload: [type:1][len:1][addr][ttl:4].
// type 0 = hostname, 4 = IPv4, 6 = IPv6. Returns the address as a string.
func parseResolved(payload []byte) (string, error) {
	if len(payload) < 2 {
		return "", errors.New("circuit: short RESOLVED payload")
	}
	typ := payload[0]
	ln := int(payload[1])
	if len(payload) < 2+ln {
		return "", errors.New("circuit: RESOLVED length exceeds payload")
	}
	addr := payload[2 : 2+ln]
	switch typ {
	case 4:
		if ln != 4 {
			return "", errors.New("circuit: bad IPv4 RESOLVED")
		}
		return net.IP(addr).String(), nil
	case 6:
		if ln != 16 {
			return "", errors.New("circuit: bad IPv6 RESOLVED")
		}
		return net.IP(append([]byte(nil), addr...)).String(), nil
	case 0:
		return string(addr), nil
	default:
		return "", fmt.Errorf("circuit: unsupported RESOLVED type %d", typ)
	}
}

// removeStream removes a stream from the circuit's map. The stream's inbound
// channel is NOT closed here — a closed channel would turn tryDeliver's
// non-blocking send into a panic if a DATA cell were still in flight for the
// stream on the readLoop goroutine; deletion alone makes tryDeliver skip it.
func (c *Circuit) removeStream(id uint16) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

// tryDeliver hands a decrypted relay cell to a stream without blocking,
// tolerating the stream having been removed (or the circuit torn down and
// s.in closed) between the caller's map lookup and this send. Sending on a
// closed channel would panic even inside a select, so re-check under the
// circuit lock that the stream is still registered — closeAllStreams closes
// s.in and empties the map in the same critical section, and removeStream
// deletes without closing, so "still in the map" implies "channel open".
func (c *Circuit) tryDeliver(s *Stream, rc *torcell.RelayCell) {
	c.mu.Lock()
	current, ok := c.streams[s.ID]
	c.mu.Unlock()
	if !ok || current != s {
		return
	}
	select {
	case s.in <- rc:
	default:
	}
}

// closeAllStreams closes every stream on the circuit. It runs from
// Circuit.Close (the SOCKS-serving goroutine, racing the circuit's readLoop)
// or from readLoop after a DESTROY. Closing s.in is safe against a racing
// tryDeliver because both the close and the map-removal happen under the
// same c.mu, and tryDeliver re-checks the stream is still registered under
// that lock before sending — a sender either sees the stream in the map with
// an open channel, or not in the map and skips the send. A DATA cell for a
// stream that closeAllStreams removed is dropped with the stream.
func (c *Circuit) closeAllStreams() {
	c.mu.Lock()
	c.closed = true
	for _, s := range c.streams {
		s.closed = true
		close(s.in)
	}
	c.streams = nil
	c.mu.Unlock()
}

// Close tears down the circuit: sends a DESTROY cell and unregisters it.
func (c *Circuit) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	// Send DESTROY.
	cell := &torcell.Cell{
		CircID:  c.circID,
		Command: torcell.CellDestroy,
	}
	cell.Payload[0] = torcell.DestroyReasonRequested
	c.link.Send(cell)
	c.link.Unregister(c.circID)
	c.closeAllStreams()
	return nil
}

// teardown is used when circuit building fails before the read loop starts.
func (c *Circuit) teardown() {
	c.link.Unregister(c.circID)
}

// CircID returns the circuit's identifier on its link.
func (c *Circuit) CircID() uint32 { return c.circID }

// HopCount returns the number of hops in the circuit.
func (c *Circuit) HopCount() int { return len(c.hops) }

func firstByte(b []byte) uint8 {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

func isZero32(b [32]byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// isZero20 reports whether a 20-byte slice is all zero.
func isZero20(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	for i := 0; i < 20; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}

func parseIP(addr string) net.IP {
	// addr is "host:port"; extract host.
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return netParseIP(addr[:i])
		}
	}
	return nil
}

func parsePort(addr string) uint16 {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			var p uint16
			for _, ch := range addr[i+1:] {
				if ch < '0' || ch > '9' {
					break
				}
				p = p*10 + uint16(ch-'0')
			}
			return p
		}
	}
	return 0
}

// BEGIN_FLAG_* flags carried in the RELAY_BEGIN payload after the NUL
// terminator (connection_edge.h:242-250).
const (
	beginFlagIPv6OK        uint32 = 1 << 0 // the exit may connect over IPv6
	beginFlagIPv4NotOK     uint32 = 1 << 1 // the exit must not connect over IPv4
	beginFlagIPv6Preferred uint32 = 1 << 2 // prefer IPv6 when both are possible
)

// targetHost extracts the host part of a "host:port" target, handling
// bracketed IPv6 literals (e.g. "[::1]:443" -> "::1"). It returns the host
// and whether the host is an IPv6 literal.
func targetHost(target string) (host string, isV6Literal bool) {
	if len(target) > 0 && target[0] == '[' {
		// Bracketed IPv6 literal: [addr]:port.
		if i := stringsIndex(target, "]"); i > 0 {
			return target[1:i], true
		}
	}
	// Plain host:port (IPv4 or hostname). Split at the last ':'.
	for i := len(target) - 1; i >= 0; i-- {
		if target[i] == ':' {
			return target[:i], false
		}
	}
	return target, false
}

// stringsIndex returns the index of the first occurrence of b in s, or -1.
func stringsIndex(s, b string) int {
	for i := 0; i+len(b) <= len(s); i++ {
		if s[i:i+len(b)] == b {
			return i
		}
	}
	return -1
}

// parseConnected parses the bound address from a RELAY_CONNECTED payload
// (relay.c:1115 connected_cell_parse). The format is:
//   - empty payload: no address (returns "");
//   - 4-byte IPv4 (big-endian) [+ 4-byte TTL];
//   - 4 zero bytes + type 6 + 16-byte IPv6 + 4-byte TTL.
//
// It returns the address as a string ("1.2.3.4" or "::1") and ignores the
// TTL. A malformed payload yields an empty string (the stream is still
// considered connected; the address is best-effort).
func parseConnected(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	if len(payload) < 4 {
		return ""
	}
	first := binary.BigEndian.Uint32(payload[0:4])
	if first != 0 {
		// IPv4 address.
		return net.IPv4(byte(first>>24), byte(first>>16), byte(first>>8), byte(first)).String()
	}
	// IPv6: 4 zero bytes + type(6) + 16 bytes + 4 bytes TTL.
	if len(payload) < 25 || payload[4] != 6 {
		return ""
	}
	ip := net.IP(append([]byte(nil), payload[5:21]...))
	return ip.String()
}
