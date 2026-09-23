// Package link implements the Tor link layer: a TLS connection to a relay
// and the v3 link handshake (VERSIONS -> CERTS -> AUTH_CHALLENGE ->
// AUTHENTICATE -> NETINFO). After the handshake completes, the Link exposes
// a cell channel over which circuits can be built.
//
// This mirrors src/core/or/connection_or.c and src/core/or/channeltls.c.
package link

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/proxy/tor-go/internal/proxy"
	"github.com/proxy/tor-go/internal/torcell"
)

// sha1Of returns the SHA-1 digest of b.
func sha1Of(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}

// Link protocol versions we support. Tor's current link protocol is 5; we
// advertise 4 and 5 (4-byte circuit IDs, RELAY_EARLY, padding negotiation).
var supportedVersions = []uint16{4, 5}

// MinLinkProtocol is the lowest link protocol version we will accept.
const MinLinkProtocol = 4

// MaxCellSize is the maximum cell size we negotiate (we use fixed 514-byte
// cells with 4-byte circuit IDs).
const MaxCellSize = torcell.TotalSize4

// Link is an established TLS channel to a relay, past the link handshake.
// It multiplexes cells for many circuits over a single TCP+TLS connection.
type Link struct {
	conn   net.Conn
	codec  *torcell.Codec
	proto  uint16 // negotiated link protocol version

	// Circuits registered on this link, keyed by CircID. Incoming cells are
	// dispatched to the channel associated with the cell's CircID.
	mu       sync.RWMutex
	circuits map[uint32]chan *torcell.Cell
	nextID   uint32

	// closed when the read loop exits.
	done chan struct{}
	err  error

	// gotNetinfo is set if the server's NETINFO arrived during the
	// handshake-drain step, so awaitNetinfo can return immediately.
	gotNetinfo bool
}

// RouterIdentity is the 20-byte SHA-1 identity digest of a relay, plus its
// Curve25519 onion key, as advertised in the consensus. This is everything
// the link + circuit layers need to talk to a relay.
type RouterIdentity struct {
	// Nickname is the relay's nickname (informational).
	Nickname string
	// IDDigest is the 20-byte SHA-1 identity fingerprint.
	IDDigest [20]byte
	// Ed25519ID is the 32-byte ed25519 identity (may be zero for older
	// relays).
	Ed25519ID [32]byte
	// OnionKey is the Curve25519 ntor onion key.
	OnionKey [32]byte
	// Address is the relay's IP and OR port.
	Address string
}

// Dial connects to addr over TCP, wraps it in TLS (using the Tor
// ciphersuite profile: any modern TLS 1.3/1.2 config is acceptable for a
// client), and performs the v3 link handshake as the initiator (client).
//
// The remote relay's expected identity digest, if non-empty, is checked
// against the certificate presented by the relay. Dial does not use an
// upstream proxy; see DialWithUpstream to reach relays through a SOCKS5
// proxy (e.g. socks5://127.0.0.1:7890).
func Dial(ctx context.Context, addr string, expectedIDDigest []byte) (*Link, error) {
	return DialWithUpstream(ctx, "", addr, expectedIDDigest)
}

// DialWithUpstream is like Dial but establishes the TCP connection to addr
// through the SOCKS5 proxy at upstreamAddr (e.g. "127.0.0.1:7890"). If
// upstreamAddr is empty, the connection is dialed directly. The TLS link
// handshake and identity check are then layered on top of the (possibly
// tunneled) TCP connection.
func DialWithUpstream(ctx context.Context, upstreamAddr, addr string, expectedIDDigest []byte) (*Link, error) {
	tcpConn, err := proxy.Dial(ctx, upstreamAddr, addr)
	if err != nil {
		return nil, fmt.Errorf("link: dial %s: %w", addr, err)
	}

	tlsCfg := &tls.Config{
		// Tor relays present a self-signed cert whose subject CN is the
		// relay's nickname and whose cert DER, when hashed with SHA-1, gives
		// the identity digest. We do not verify against a CA; instead we
		// verify the digest ourselves after the handshake (see verifyPeer).
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("link: tls handshake: %w", err)
	}

	// Verify the relay's identity digest if one was provided.
	if len(expectedIDDigest) == 20 {
		if err := verifyPeer(tlsConn, expectedIDDigest); err != nil {
			tlsConn.Close()
			return nil, err
		}
	}

	l := &Link{
		conn:     tlsConn,
		codec:    torcell.NewCodec(tlsConn, 4),
		circuits: make(map[uint32]chan *torcell.Cell),
		done:     make(chan struct{}),
	}
	if err := l.handshake(ctx); err != nil {
		tlsConn.Close()
		return nil, err
	}
	go l.readLoop()
	return l, nil
}

// verifyPeer checks that the relay's TLS certificate hashes to the expected
// 20-byte SHA-1 identity digest. Tor derives the identity digest from the
// SHA-1 of the DER-encoded certificate (for the legacy RSA link cert).
func verifyPeer(tlsConn *tls.Conn, expectedIDDigest []byte) error {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("link: peer presented no certificate")
	}
	// The first certificate is the relay's link authentication cert.
	der := state.PeerCertificates[0].Raw
	sum := sha1Digest(der)
	if !bytes.Equal(sum, expectedIDDigest) {
		return fmt.Errorf("link: identity digest mismatch (got %x, want %x)", sum, expectedIDDigest)
	}
	return nil
}

func sha1Digest(b []byte) []byte {
	// Tor's identity digest is the SHA-1 of the DER-encoded link cert.
	return sha1Of(b)
}

// handshake performs the v3 link handshake as the initiator.
func (l *Link) handshake(ctx context.Context) error {
	// 1. Send VERSIONS cell listing the protocols we support.
	versionsPayload := make([]byte, 2*len(supportedVersions))
	for i, v := range supportedVersions {
		binary.BigEndian.PutUint16(versionsPayload[2*i:], v)
	}
	if err := l.codec.WriteVarCell(&torcell.VarCell{
		Command: torcell.CellVersions,
		Payload: versionsPayload,
	}); err != nil {
		return err
	}

	// 2. Read the server's VERSIONS cell and pick the highest common version.
	vc, err := l.codec.ReadVarCell()
	if err != nil {
		return fmt.Errorf("link: read versions: %w", err)
	}
	if vc.Command != torcell.CellVersions {
		return fmt.Errorf("link: expected VERSIONS, got %d", vc.Command)
	}
	l.proto, err = pickVersion(vc.Payload)
	if err != nil {
		return err
	}
	if l.proto < MinLinkProtocol {
		return fmt.Errorf("link: server link protocol %d below our minimum %d", l.proto, MinLinkProtocol)
	}
	// With protocol >= 4, circuit IDs are 4 bytes.
	l.codec.SetCircIDWidth(4)

	// 3. As a client, we skip CERTS/AUTH_CHALLENGE/AUTHENTICATE (we are not
	//    authenticating ourselves to the relay; only the relay authenticates
	//    to us via its TLS cert, already verified). We do, however, consume
	//    any CERTS / AUTH_CHALLENGE cells the relay sends so they don't
	//    confuse the read loop, then send and expect NETINFO.
	if err := l.consumeHandshakeCells(ctx); err != nil {
		return err
	}

	// 4. Send NETINFO.
	if err := l.sendNetinfo(); err != nil {
		return err
	}

	// 5. Read the server's NETINFO.
	if err := l.awaitNetinfo(ctx); err != nil {
		return err
	}
	return nil
}

// consumeHandshakeCells reads and discards CERTS and AUTH_CHALLENGE cells
// that the relay sends during the handshake. A client is not required to
// process them, but must drain them from the channel.
func (l *Link) consumeHandshakeCells(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	for {
		if time.Now().After(deadline) {
			return errors.New("link: handshake timed out")
		}
		l.conn.SetReadDeadline(deadline)
		msg, err := l.codec.ReadAny()
		if err != nil {
			return fmt.Errorf("link: read during handshake: %w", err)
		}
		l.conn.SetReadDeadline(time.Time{})
		switch c := msg.(type) {
		case *torcell.VarCell:
			switch c.Command {
			case torcell.CellCerts, torcell.CellAuthChallenge:
				continue
			case torcell.CellVPadding:
				continue
			case torcell.CellVersions:
				// already handled
				continue
			default:
				// Unknown var cell during handshake; ignore.
				continue
			}
		case *torcell.Cell:
			if c.Command == torcell.CellNetinfo {
				// Server sent NETINFO before us; that's fine. We still send
				// ours. Stash it so awaitNetinfo is satisfied.
				l.gotNetinfo = true
				return nil
			}
			// Ignore other fixed cells during handshake.
		}
	}
}

// awaitNetinfo waits for the server's NETINFO cell (if not already received).
func (l *Link) awaitNetinfo(ctx context.Context) error {
	if l.gotNetinfo {
		return nil
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	for {
		if time.Now().After(deadline) {
			return errors.New("link: netinfo timeout")
		}
		l.conn.SetReadDeadline(deadline)
		msg, err := l.codec.ReadAny()
		if err != nil {
			return fmt.Errorf("link: read netinfo: %w", err)
		}
		l.conn.SetReadDeadline(time.Time{})
		switch c := msg.(type) {
		case *torcell.Cell:
			if c.Command == torcell.CellNetinfo {
				return nil
			}
		case *torcell.VarCell:
			// ignore
		}
	}
}

// sendNetinfo sends a NETINFO cell with our timestamp, the peer's observed
// address, and (optionally) our own address.
func (l *Link) sendNetinfo() error {
	var buf bytes.Buffer
	// Timestamp (4 bytes, big-endian).
	binary.Write(&buf, binary.BigEndian, uint32(time.Now().Unix()))
	// Other (peer) address.
	peerIP, peerPort := parseHostPort(l.conn.RemoteAddr().String())
	writeNetinfoAddr(&buf, peerIP)
	_ = peerPort
	// Number of my addresses (we send 0 as a client; we have no public
	// address to advertise).
	buf.WriteByte(0)

	cell := &torcell.Cell{Command: torcell.CellNetinfo}
	copy(cell.Payload[:], buf.Bytes())
	return l.codec.WriteCell(cell)
}

// writeNetinfoAddr writes a Tor NETINFO address: [type:1][len:1][addr].
// type 4 = IPv4 (4 bytes), type 6 = IPv6 (16 bytes).
func writeNetinfoAddr(w *bytes.Buffer, ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		w.WriteByte(4)
		w.WriteByte(4)
		w.Write(v4)
		return
	}
	v6 := ip.To16()
	if v6 != nil {
		w.WriteByte(6)
		w.WriteByte(16)
		w.Write(v6)
		return
	}
	// Unknown / empty: write a zero-length hostname.
	w.WriteByte(0)
	w.WriteByte(0)
}

func parseHostPort(s string) (net.IP, string) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, s
	}
	return net.ParseIP(host), port
}

func pickVersion(payload []byte) (uint16, error) {
	if len(payload)%2 != 0 {
		return 0, errors.New("link: malformed VERSIONS payload")
	}
	best := uint16(0)
	for i := 0; i+2 <= len(payload); i += 2 {
		v := binary.BigEndian.Uint16(payload[i:])
		for _, sv := range supportedVersions {
			if v == sv && v > best {
				best = v
			}
		}
	}
	if best == 0 {
		return 0, errors.New("link: no common link protocol version")
	}
	return best, nil
}

// readLoop continuously reads cells and dispatches them to the circuit
// registered for the cell's CircID. It exits when the connection closes.
func (l *Link) readLoop() {
	defer close(l.done)
	for {
		msg, err := l.codec.ReadAny()
		if err != nil {
			l.mu.Lock()
			l.err = err
			l.mu.Unlock()
			return
		}
		cell, ok := msg.(*torcell.Cell)
		if !ok {
			// Variable-length cells after handshake (e.g. padding). Ignore.
			continue
		}
		l.mu.RLock()
		ch, ok := l.circuits[cell.CircID]
		l.mu.RUnlock()
		if !ok {
			// Cell for unknown circuit; ignore (could be a late cell after
			// teardown).
			continue
		}
		select {
		case ch <- cell:
		default:
			// Circuit's inbound queue is full; drop. A well-behaved peer
			// respects flow control, so this should be rare.
		}
	}
}

// Register allocates a new circuit ID on this link and returns it along with
// a channel that receives inbound cells for that circuit. The caller must
// call Unregister when the circuit is torn down.
func (l *Link) Register() (uint32, <-chan *torcell.Cell, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Circuit IDs chosen by the initiator use the high bit clear; the
	// responder uses the high bit set. We pick the next odd-ish ID.
	id := l.nextID
	if id == 0 {
		// Start at a random odd number to avoid collisions after reconnect.
		var b [4]byte
		rand.Read(b[:])
		id = binary.BigEndian.Uint32(b[:]) & 0x7FFFFFFF
		if id == 0 {
			id = 1
		}
		if id%2 == 0 {
			id++
		}
	}
	// Ensure uniqueness.
	for {
		if _, ok := l.circuits[id]; !ok {
			break
		}
		id += 2
	}
	l.nextID = id + 2
	ch := make(chan *torcell.Cell, 64)
	l.circuits[id] = ch
	return id, ch, nil
}

// Unregister removes a circuit's dispatch entry.
func (l *Link) Unregister(id uint32) {
	l.mu.Lock()
	delete(l.circuits, id)
	l.mu.Unlock()
}

// Send writes a cell on the link.
func (l *Link) Send(cell *torcell.Cell) error {
	return l.codec.WriteCell(cell)
}

// Protocol returns the negotiated link protocol version.
func (l *Link) Protocol() uint16 { return l.proto }

// Close closes the underlying connection.
func (l *Link) Close() error {
	return l.conn.Close()
}

// Wait blocks until the read loop exits and returns the error that caused it.
func (l *Link) Wait() error {
	<-l.done
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.err
}

// RemoteAddr returns the address of the peer.
func (l *Link) RemoteAddr() net.Addr { return l.conn.RemoteAddr() }

// ErrClosed is returned when operating on a closed link.
var ErrClosed = errors.New("link: closed")
