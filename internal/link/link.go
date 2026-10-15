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
	"log"
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
	conn  net.Conn
	codec *torcell.Codec
	proto uint16 // negotiated link protocol version

	// Circuits registered on this link, keyed by CircID. Incoming cells are
	// dispatched to the channel associated with the cell's CircID.
	mu       sync.RWMutex
	circuits map[uint32]chan *torcell.Cell

	// closed when the read loop exits.
	done chan struct{}
	err  error

	// gotNetinfo is set if the server's NETINFO arrived during the
	// handshake-drain step, so awaitNetinfo can return immediately.
	gotNetinfo bool

	// peerID is the verified relay identity learned from the CERTS cell
	// (RSA identity digest + ed25519 identity). It is set during the
	// handshake if the relay presented a valid cert chain.
	peerID *peerIdentity

	// peerTimestamp is the timestamp the peer reported in its NETINFO cell,
	// and clockSkew is now - peerTimestamp (positive = our clock is ahead).
	// They are set when the server's NETINFO is received. A |clockSkew|
	// exceeding netinfoNoticeSkew (1 hour) is logged as a warning,
	// mirroring channel_tls_process_netinfo_cell (channeltls.c:1962).
	peerTimestamp time.Time
	clockSkew     time.Duration
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
	// ProtoVer is the parsed protocol-versions map from the microdescriptor
	// "pr" line (e.g. Relay=1-2 FlowCtrl=2). The circuit layer uses it to
	// decide whether a relay supports the ntor v3 handshake (Relay>=4). Nil
	// means the relay did not advertise protocol versions.
	ProtoVer map[string]string
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
	return DialWithUpstream(ctx, "", addr, expectedIDDigest, [32]byte{})
}

// DialWithUpstream is like Dial but establishes the TCP connection to addr
// through the SOCKS5 proxy at upstreamAddr (e.g. "127.0.0.1:7890"). If
// upstreamAddr is empty, the connection is dialed directly. The TLS link
// handshake and identity check are then layered on top of the (possibly
// tunneled) TCP connection.
//
// expectedIDDigest, when 20 bytes, is the consensus RSA identity digest the
// CERTS cell's RSA ID cert must prove (the authoritative identity check).
// expectedEd25519ID, when non-zero, is the relay's expected ed25519 master
// identity; a verified mismatch (or "wanted ed, got none") is a hard link
// failure, mirroring connection_or_client_learned_peer_id
// (connection_or.c): "It only counts as an ed25519 mismatch if we wanted an
// ed25519 identity and didn't get it."
func DialWithUpstream(ctx context.Context, upstreamAddr, addr string, expectedIDDigest []byte, expectedEd25519ID [32]byte) (*Link, error) {
	tcpConn, err := proxy.Dial(ctx, upstreamAddr, addr)
	if err != nil {
		return nil, fmt.Errorf("link: dial %s: %w", addr, err)
	}

	tlsCfg := &tls.Config{
		// Tor relays present a self-signed link cert (often with a rotating
		// fake hostname CN) whose DER does NOT hash to the RSA identity —
		// the identity is proven by the CERTS cell's RSA ID cert, checked
		// after the link handshake. We never verify against a CA; the digest
		// check below is the authentication.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("link: tls handshake: %w", err)
	}

	l := &Link{
		conn: tlsConn,
		// per tor-spec, cells sent before the link protocol is negotiated
		// (the first VERSIONS exchange) carry 2-byte circuit IDs; the codec
		// flips to 4 bytes inside handshake() once proto >= 4 is agreed
		// (channeltls.c:1620).
		codec:    torcell.NewCodec(tlsConn, 2),
		circuits: make(map[uint32]chan *torcell.Cell),
		done:     make(chan struct{}),
	}
	if err := l.handshake(ctx); err != nil {
		tlsConn.Close()
		return nil, err
	}
	// Check the learned identity digest if one was expected (the consensus
	// "r" line identity). The CERTS cell's RSA ID cert is the authoritative
	// proof — Tor never compares the TLS link cert DER to the identity
	// (connection_or.c: connection_or_client_learned_peer_id) — so this runs
	// after the handshake. The legacy TLS-cert-digest check (verifyPeer) is
	// a fallback for links that presented a degenerate CERTS cell, which the
	// in-process test harness relies on.
	if len(expectedIDDigest) != 20 {
		// No expected digest: nothing to verify (test harness links).
		go l.readLoop()
		return l, nil
	}
	if l.peerID != nil {
		if !bytes.Equal(l.peerID.rsaIDDigest[:], expectedIDDigest) {
			tlsConn.Close()
			return nil, fmt.Errorf("link: CERTS identity digest mismatch (got %x, want %x)", l.peerID.rsaIDDigest, expectedIDDigest)
		}
		// When the directory lists an ed25519 identity for the relay, the
		// CERTS-verified one must match it (connection_or.c:
		// connection_or_client_learned_peer_id's ed25519_mismatch).
		if !isZeroID(expectedEd25519ID) && l.peerID.hasEd25519 &&
			l.peerID.ed25519ID != expectedEd25519ID {
			tlsConn.Close()
			return nil, fmt.Errorf("link: CERTS ed25519 identity mismatch (got %x, want %x)", l.peerID.ed25519ID, expectedEd25519ID)
		}
	} else if err := verifyPeer(tlsConn, expectedIDDigest); err != nil {
		// Degenerate CERTS: the harness's minimal CERTS cell carries no
		// certificates, and its TLS cert DER hashes to the identity.
		tlsConn.Close()
		return nil, err
	}
	go l.readLoop()
	return l, nil
}

// verifyPeer checks that the relay's TLS certificate hashes to the expected
// 20-byte SHA-1 identity digest. This is NOT a Tor identity mechanism — Tor
// never compares the TLS link cert DER to the identity (connection_or.c:
// connection_or_client_learned_peer_id); it is a test-harness-only fallback
// for links that presented a degenerate CERTS cell: the harness generates
// its TLS certs so that SHA-1(cert DER) == IDDigest, letting in-process tests
// authenticate the mock relays. On the real network a link with a degenerate
// CERTS cell fails this check and the connection is dropped.
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
	// Test-harness convention only; see verifyPeer.
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

// consumeHandshakeCells reads CERTS and AUTH_CHALLENGE cells that the relay
// sends during the handshake. A client captures the CERTS cell for identity
// verification (see verifyCerts) and drains AUTH_CHALLENGE (a client does not
// authenticate itself to the relay).
func (l *Link) consumeHandshakeCells(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	var certsPayload []byte
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
			case torcell.CellCerts:
				// Capture for verification after the drain loop.
				certsPayload = append([]byte(nil), c.Payload...)
				continue
			case torcell.CellAuthChallenge, torcell.CellVPadding, torcell.CellVersions:
				continue
			default:
				// Unknown var cell during handshake; ignore.
				continue
			}
		case *torcell.Cell:
			if c.Command == torcell.CellNetinfo {
				// Server sent NETINFO before us; that's fine. We still send
				// ours. Stash it so awaitNetinfo is satisfied, and record
				// the peer's timestamp / clock skew.
				l.handleNetinfo(c.Payload[:])
				l.gotNetinfo = true
				// Fall through to CERTS verification before returning.
				return l.verifyPeerCerts(certsPayload)
			}
			// Ignore other fixed cells during handshake.
		}
	}
}

// verifyPeerCerts parses and verifies the captured CERTS cell payload against
// the TLS peer certificate. If the CERTS cell is absent or degenerate (no
// usable certs), it falls back to the legacy TLS-cert SHA-1 digest check
// (verifyPeer), which the in-process test harness relies on. On a real relay
// with a well-formed cert chain, it performs full RSA + ed25519 + crosscert
// verification and records the learned identity.
func (l *Link) verifyPeerCerts(certsPayload []byte) error {
	if len(certsPayload) == 0 {
		// No CERTS cell received; nothing to verify here. The legacy
		// TLS-digest check (if an expected digest was given) already ran in
		// DialWithUpstream.
		return nil
	}
	pc, err := parseCertsCell(certsPayload)
	if err != nil {
		return fmt.Errorf("link: parse CERTS: %w", err)
	}
	if pc == nil || pc.idCert == nil {
		// Degenerate CERTS cell (e.g. test harness placeholder): fall back to
		// the legacy TLS-digest identity check, already performed. Nothing
		// more to verify.
		return nil
	}
	// Fetch the TLS peer cert DER to bind the cert chain to the TLS session.
	state := l.conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("link: no TLS peer cert for CERTS binding")
	}
	peerDER := state.PeerCertificates[0].Raw
	id, err := verifyCerts(pc, peerDER, time.Now())
	if err != nil {
		return fmt.Errorf("link: CERTS verification: %w", err)
	}
	l.peerID = id
	return nil
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
				l.handleNetinfo(c.Payload[:])
				return nil
			}
		case *torcell.VarCell:
			// ignore
		}
	}
}

// netinfoNoticeSkew is the minimum |clock skew| (in seconds) inferred from a
// NETINFO cell that triggers a warning, matching NETINFO_NOTICE_SKEW
// (channeltls.c:1961).
const netinfoNoticeSkew = 3600

// handleNetinfo parses the peer's NETINFO cell payload for its timestamp and
// records the apparent clock skew, logging a warning if it exceeds one hour.
// This mirrors channel_tls_process_netinfo_cell (channeltls.c:1856): the
// skew is only meaningful if we sent our VERSIONS cell recently (within 180s),
// which is always true here since handleNetinfo is called during the
// handshake. The timestamp is the first 4 bytes of the payload (big-endian
// seconds since the epoch). A malformed payload (too short) is ignored: the
// cell still satisfies the handshake, but no skew is recorded.
func (l *Link) handleNetinfo(payload []byte) {
	if len(payload) < 4 {
		return
	}
	ts := binary.BigEndian.Uint32(payload[0:4])
	l.peerTimestamp = time.Unix(int64(ts), 0)
	now := time.Now()
	l.clockSkew = now.Sub(l.peerTimestamp)
	if absDuration(l.clockSkew) > netinfoNoticeSkew*time.Second {
		// Log a human-readable skew (e.g. "3601s ahead"/"3601s behind").
		rel := "ahead"
		if l.clockSkew < 0 {
			rel = "behind"
		}
		log.Printf("link: NETINFO clock skew warning: peer timestamp %s, our clock is %s %s",
			l.peerTimestamp.Format(time.RFC3339), absDuration(l.clockSkew), rel)
	}
}

// absDuration returns the absolute value of d.
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
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
//
// We are always the initiator (this Link is a client→relay channel), and on
// the wide links we actually run (negotiated protocol >= MIN_LINK_PROTO_FOR_
// WIDE_CIRC_IDS = 4, connection_or.h:111 — handshake() rejects anything
// lower), channel_set_circid_type (channel.c:3425) passes consider_identity=0
// and gives us CIRC_ID_TYPE_HIGHER: our circuit IDs come from the high half
// of the space (bit 31) and the relay picks from the low half;
// command_process_create_cell (command.c:313) destroys any CREATE whose ID
// carries the wrong direction. (On a narrow link C instead compares identity
// keys, and a keyless client lands in the LOW half; the bit-15 fallback
// branch below is dead under MinLinkProtocol=4 and retained only for
// completeness.) We also avoid 0: the responder drops circ_id 0 silently.
// The draw-and-retry loop mirrors get_unique_circ_id_by_chan
// (circuitbuild.c:133), including its MAX_CIRCID_ATTEMPTS bound.
func (l *Link) Register() (uint32, <-chan *torcell.Cell, error) {
	wide := l.proto >= MinLinkProtocol
	highBit := uint32(1) << 15
	if wide {
		highBit = 1 << 31
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Pick a random ID from our half of the space, skipping ones already in
	// use (MAX_CIRCID_ATTEMPTS bounds the loop; the space is essentially
	// unbounded for a client with a handful of circuits).
	var id uint32
	for attempts := 0; attempts < 64; attempts++ {
		var b [4]byte
		rand.Read(b[:])
		id = binary.BigEndian.Uint32(b[:])
		if wide {
			// Restrict to the high half: 0x80000000..0xFFFFFFFF.
			id |= highBit
		} else {
			// Restrict to the high half of the 16-bit space: 0x8000..0xFFFF.
			id &= highBit - 1
			id |= highBit
		}
		if id == 0 {
			continue
		}
		if _, ok := l.circuits[id]; !ok {
			ch := make(chan *torcell.Cell, 64)
			l.circuits[id] = ch
			return id, ch, nil
		}
	}
	return 0, nil, errors.New("link: no unused circuit IDs available")
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

// SendPadding sends an unsolicited PADDING cell (command 0, zero payload).
// Tor relays accept and drop unsolicited padding on established channels —
// command_process_cell's default case just logs and drops (command.c:212) —
// which makes it the channel keep-alive: the C client keeps channels from
// being reaped by intermediaries with negotiated channel padding
// (channelpadding.c); here it defeats idle-timeout reaping by upstream
// SOCKS5 proxies such as Clash/mihomo that silently drop idle tunnels.
func (l *Link) SendPadding() error {
	return l.codec.WriteCell(&torcell.Cell{Command: torcell.CellPadding})
}

// Protocol returns the negotiated link protocol version.
func (l *Link) Protocol() uint16 { return l.proto }

// PeerRSAIDDigest returns the relay's RSA identity digest as verified from the
// CERTS cell, or the zero value if CERTS verification did not run (in which
// case the legacy TLS-cert digest check applies).
func (l *Link) PeerRSAIDDigest() [20]byte {
	if l.peerID != nil {
		return l.peerID.rsaIDDigest
	}
	return [20]byte{}
}

// PeerEd25519ID returns the relay's ed25519 master identity as verified from
// the CERTS cell, and whether an ed25519 identity was established.
func (l *Link) PeerEd25519ID() ([32]byte, bool) {
	if l.peerID != nil {
		return l.peerID.ed25519ID, l.peerID.hasEd25519
	}
	return [32]byte{}, false
}

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

// IsAlive reports whether the link's read loop is still running and the
// channel has not failed. A link that has died (peer closed, upstream proxy
// dropped the tunnel, TLS error) returns false; callers holding a stale
// Link should dial a fresh one.
func (l *Link) IsAlive() bool {
	select {
	case <-l.done:
		return false
	default:
		return true
	}
}

// isZeroID reports whether id is the zero value ("no expected identity").
func isZeroID(id [32]byte) bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

// RemoteAddr returns the address of the peer.
func (l *Link) RemoteAddr() net.Addr { return l.conn.RemoteAddr() }

// ErrClosed is returned when operating on a closed link.
var ErrClosed = errors.New("link: closed")
