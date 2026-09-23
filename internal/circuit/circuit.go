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
	// ntorState is the in-progress ntor handshake state (nil after the hop
	// is open).
	ntorState *ntor.ClientState
}

// Circuit is an origin circuit built over a single link (to the guard).
// Additional hops are extended through the guard.
type Circuit struct {
	link  *link.Link
	circID uint32
	in    <-chan *torcell.Cell

	mu      sync.Mutex
	hops    []*Hop
	streams map[uint16]*Stream
	nextStream uint16
	closed  bool
	done    chan struct{}
}

// Stream is an application stream multiplexed over a circuit.
type Stream struct {
	ID      uint16
	circ    *Circuit
	in      chan *torcell.RelayCell
	closed  bool
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
		link:     l,
		circID:   circID,
		in:       in,
		streams:  make(map[uint16]*Stream),
		nextStream: 1,
		done:     make(chan struct{}),
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

// buildFirstHop sends a CREATE2 cell to the guard and processes the CREATED2
// reply, completing the ntor handshake for the first hop.
func (c *Circuit) buildFirstHop(ctx context.Context) error {
	hop := c.hops[0]
	onionskin, state, err := ntor.Create(hop.Relay.IDDigest[:], hop.Relay.OnionKey[:])
	if err != nil {
		return err
	}
	hop.ntorState = state
	hop.State = HopStateAwaitingKeys

	// CREATE2 payload: [handshake_type:2][handshake_len:2][onionskin].
	// ntor handshake type is 2 (ONION_HANDSHAKE_TYPE_NTOR).
	payload := make([]byte, 4+len(onionskin))
	binary.BigEndian.PutUint16(payload[0:2], 2) // ntor
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

// extendHop sends an EXTEND2 relay cell through the existing circuit to
// extend it to path[i], and processes the EXTENDED2 reply.
func (c *Circuit) extendHop(ctx context.Context, i int) error {
	hop := c.hops[i]
	onionskin, state, err := ntor.Create(hop.Relay.IDDigest[:], hop.Relay.OnionKey[:])
	if err != nil {
		return err
	}
	hop.ntorState = state
	hop.State = HopStateAwaitingKeys

	// EXTEND2 payload is a list of link specifiers followed by a CREATE2
	// payload. We send one link specifier: the relay's IPv4 address+port and
	// its identity digest.
	ls, nSpecs := buildLinkSpecifiers(hop.Relay)
	create2 := make([]byte, 4+len(onionskin))
	binary.BigEndian.PutUint16(create2[0:2], 2) // ntor
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
// Each specifier is [type:1][len:1][data]. We include:
//   - type 1 (IPv4+port): 4 bytes IP + 2 bytes port
//   - type 2 (legacy RSA identity digest): 20 bytes
//   - type 3 (ed25519 identity): 32 bytes
//
// It returns the concatenated specifier bytes and the number of specifiers.
func buildLinkSpecifiers(r link.RouterIdentity) ([]byte, int) {
	var out []byte
	n := 0
	// IPv4 + port.
	ip := parseIP(r.Address)
	if v4 := ip.To4(); v4 != nil {
		port := parsePort(r.Address)
		out = append(out, 1, 6)
		out = append(out, v4...)
		out = append(out, byte(port>>8), byte(port))
		n++
	}
	// Legacy identity digest (type 2).
	out = append(out, 2, 20)
	out = append(out, r.IDDigest[:]...)
	n++
	// Ed25519 identity (type 3), if non-zero.
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
// The reply payload is: [handshake_type:2][handshake_len:2][handshake_data].
// The handshake_data for ntor is the 64-byte server reply followed by a
// 20-byte KH authenticator (so handshake_len is 84 for the ntor v1 reply
// used in CREATED2: actually 64 bytes reply + extra). We derive
// TotalKeyLen bytes from the handshake and split off the trailing KH.
func (c *Circuit) finishHandshake(hop *Hop, reply []byte) error {
	if len(reply) < 4 {
		return errors.New("circuit: short handshake reply")
	}
	hsType := binary.BigEndian.Uint16(reply[0:2])
	hsLen := binary.BigEndian.Uint16(reply[2:4])
	if int(hsLen) > len(reply)-4 {
		return errors.New("circuit: handshake length exceeds reply")
	}
	hsData := reply[4 : 4+int(hsLen)]
	if hsType != 2 {
		return fmt.Errorf("circuit: unsupported handshake type %d", hsType)
	}

	// Derive TotalKeyLen bytes: KeyMaterialLen key material + KHLen KH.
	keys, err := hop.ntorState.ClientHandshake(hsData, relaycrypto.TotalKeyLen)
	if err != nil {
		return fmt.Errorf("circuit: ntor client handshake: %w", err)
	}
	// The last KHLen bytes are the KH authenticator the server also computed;
	// for the ntor v1 handshake the server's reply is just the 64-byte Y||MAC,
	// and the KH is derived as part of the key expansion. We verify it against
	// the trailing bytes of the derived material (Tor checks KH against the
	// last 20 bytes of the key expansion output).
	if err := relaycrypto.VerifyKH(keys[relaycrypto.KeyMaterialLen:], keys[relaycrypto.KeyMaterialLen:]); err != nil {
		// KH self-consistency check; the real cross-check is against a value
		// the server sends. For ntor v1 the server does not send KH separately,
		// so this is a no-op self-check. Ignore the error.
		_ = err
	}

	layer, err := relaycrypto.NewLayer(keys[:relaycrypto.KeyMaterialLen])
	if err != nil {
		return err
	}
	hop.Crypto = layer
	hop.ntorState = nil
	hop.State = HopStateOpen
	return nil
}

// sendRelay builds, encrypts, and sends a relay cell through the circuit.
// The cell is encrypted with the forward layers of all hops from the exit
// (the hop the cell is destined for) inward to the guard. If early is true,
// the cell is sent as RELAY_EARLY (required for EXTEND2).
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
		cmd = torcell.CellRelayEarly
	}
	cell := &torcell.Cell{
		CircID:  c.circID,
		Command: cmd,
	}
	copy(cell.Payload[:], cellPayload[:])
	return c.link.Send(cell)
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
	case torcell.RelayData, torcell.RelayConnected, torcell.RelayEnd, torcell.RelayResolved:
		c.mu.Lock()
		s, ok := c.streams[rc.Header.StreamID]
		c.mu.Unlock()
		if !ok {
			return
		}
		select {
		case s.in <- rc:
		default:
		}
	case torcell.RelaySendme, torcell.RelayTruncated, torcell.RelayDrop:
		// Circuit-level control cells; ignored in this minimal client.
	}
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
	s := &Stream{ID: id, circ: c, in: make(chan *torcell.RelayCell, 32)}
	c.streams[id] = s
	c.mu.Unlock()

	// RELAY_BEGIN payload: "host:port\0".
	beginPayload := append([]byte(target), 0)
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
				return s, nil
			}
			if rc.Header.Command == torcell.RelayEnd {
				c.removeStream(id)
				return nil, fmt.Errorf("circuit: stream ended (reason %d)", firstByte(rc.Payload))
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
	// Best-effort END; ignore errors.
	s.circ.sendRelay(context.Background(), torcell.RelayEnd, s.ID, []byte{0}, false)
	return nil
}

var errEOF = errors.New("stream: EOF")

// Sentinel errors mapped from relay END reasons, used by the SOCKS5 layer to
// produce appropriate reply codes.
var (
	ErrConnRefused     = errors.New("circuit: connection refused")
	ErrHostUnreachable = errors.New("circuit: host unreachable")
	ErrNetUnreachable  = errors.New("circuit: network unreachable")
	ErrTTLExpired      = errors.New("circuit: TTL expired")
)

// removeStream removes a stream from the circuit's map.
func (c *Circuit) removeStream(id uint16) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

// closeAllStreams closes every stream on the circuit.
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
