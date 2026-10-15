// Package testharness provides an in-process mock Tor relay server for
// integration and end-to-end tests. A MockRelay speaks enough of the Tor link
// and circuit protocols — TLS link handshake, CREATE2/CREATED2 (ntor),
// EXTEND2/EXTENDED2, and RELAY BEGIN/DATA/CONNECTED/END — that the real
// client packages (link, circuit, torclient) can build multi-hop circuits
// through a chain of mock relays and open streams that the exit relays to a
// real (loopback) TCP target.
//
// The mock is a faithful reimplementation of the server side of the protocols
// the client packages implement, so an end-to-end test exercises the same code
// paths a real guard/exit would. It is not a toy: it performs the real ntor
// server handshake, real tor1 relay crypto (reversed layers), and real
// multi-hop extension.
package testharness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/proxy/tor-go/internal/fast"
	"github.com/proxy/tor-go/internal/ntor"
	"github.com/proxy/tor-go/internal/relaycrypto"
	"github.com/proxy/tor-go/internal/torcell"
)

// RelayConfig describes one mock relay: its identity, onion keypair, and the
// TCP address it listens on. A chain of MockRelays forms a circuit path.
type RelayConfig struct {
	// Nickname is the relay's nickname (informational).
	Nickname string
	// IDDigest is the 20-byte SHA-1 identity digest. The relay's TLS cert is
	// generated so that SHA-1(cert DER) == IDDigest, which is what the client's
	// link.verifyPeer checks.
	IDDigest [20]byte
	// OnionKey is the Curve25519 onion keypair. The public key is what the
	// client uses in the ntor handshake; the secret key is held here.
	OnionKey *ntor.ServerKeyPair
	// ListenAddr is the address the relay listens on (e.g. "127.0.0.1:0").
	ListenAddr string
}

// MockRelay is a running mock relay server.
type MockRelay struct {
	cfg     RelayConfig
	ln      net.Listener
	tlsCfg  *tls.Config
	certDER []byte
	addr    string

	mu       sync.Mutex
	circuits map[uint32]*relayCircuit
	closed   bool
	wg       sync.WaitGroup

	// nextHop resolves a relay identity digest to the MockRelay that plays
	// that relay, so EXTEND2 can forward the inner CREATE2 to the right peer.
	// It is set by the Harness before the relay starts serving.
	nextHop func(idDigest [20]byte) *MockRelay
}

// relayCircuit is the per-circuit state on a relay: the relay-crypto layer
// shared with the client for this hop, and (for the exit) the open streams.
type relayCircuit struct {
	circID    uint32
	layer     *relaycrypto.Layer // crypto shared with the client for this hop
	prevHop   *relayCircuit      // the hop before us (toward the client)
	prevRelay *MockRelay         // the relay owning prevHop
	nextHop   *relayCircuit      // the hop after us (toward the exit), set on EXTEND2
	nextRelay *MockRelay         // the relay owning nextHop

	mu      sync.Mutex
	streams map[uint16]*relayStream
}

// relayStream is an exit stream: a TCP connection to the target plus the
// circuit + stream id it belongs to.
type relayStream struct {
	conn     net.Conn
	circ     *relayCircuit
	streamID uint16
}

// NewMockRelay starts a mock relay with the given config. The relay listens
// for TLS connections on cfg.ListenAddr (use "127.0.0.1:0" for an ephemeral
// port; call Addr() to learn it).
func NewMockRelay(cfg RelayConfig) (*MockRelay, error) {
	if cfg.OnionKey == nil {
		return nil, errors.New("testharness: OnionKey is nil")
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("testharness: listen: %w", err)
	}
	certDER, tlsCfg, err := generateCert(cfg.IDDigest, cfg.Nickname)
	if err != nil {
		ln.Close()
		return nil, err
	}
	r := &MockRelay{
		cfg:      cfg,
		ln:       ln,
		tlsCfg:   tlsCfg,
		certDER:  certDER,
		addr:     ln.Addr().String(),
		circuits: make(map[uint32]*relayCircuit),
	}
	return r, nil
}

// generateCert creates a self-signed TLS certificate whose SHA-1(DER) equals
// the desired 20-byte identity digest. The client's link layer verifies the
// relay's identity by hashing the presented cert, so we must produce a cert
// that hashes to exactly cfg.IDDigest. We do this by brute-forcing a small
// serial-number field: we generate candidate certs with incrementing serials
// until one hashes to a value whose first 20 bytes... — actually we cannot
// freely choose all 20 bytes of a SHA-1. Instead, we disable the client's
// digest check in tests by passing a zero expected digest (see Harness), OR
// we set the relay's IDDigest to the actual hash of the generated cert.
//
// The simplest correct approach: generate a cert, compute its SHA-1, and use
// THAT as the relay's identity digest. The Harness does this by calling
// IdentityDigest() after construction. So callers should not preset IDDigest
// in RelayConfig; the relay derives it from its cert.
func generateCert(preset [20]byte, nickname string) ([]byte, *tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// We want SHA-1(certDER) == preset. We brute-force the serial number
	// (a big.Int in the cert) to find a cert whose hash matches. SHA-1 is 20
	// bytes; finding a full preimage is infeasible. So instead we do NOT
	// preset the digest: we generate the cert and return its actual hash via
	// the caller computing sha1(certDER). The preset is ignored.
	_ = preset
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: nickname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	_ = cert
	return der, tlsCfg, nil
}

// IdentityDigest returns the SHA-1 of the relay's TLS certificate DER, which
// is the identity digest the client will see and verify.
func (r *MockRelay) IdentityDigest() [20]byte {
	sum := sha1.Sum(r.certDER)
	return sum
}

// Addr returns the relay's listen address (host:port).
func (r *MockRelay) Addr() string { return r.addr }

// OnionPublicKey returns the relay's advertised ntor onion key.
func (r *MockRelay) OnionPublicKey() [32]byte { return r.cfg.OnionKey.PubKeyB }

// SetNextHopResolver installs the function used to resolve a relay identity
// digest to the MockRelay playing that relay. Called by the Harness.
func (r *MockRelay) SetNextHopResolver(f func(idDigest [20]byte) *MockRelay) {
	r.nextHop = f
}

// Serve accepts and handles connections until Close is called.
func (r *MockRelay) Serve() error {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			r.mu.Lock()
			closed := r.closed
			r.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.handleConn(conn)
		}()
	}
}

// Close stops the relay and waits for in-flight handlers to finish.
func (r *MockRelay) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.ln.Close()
	r.wg.Wait()
	return nil
}

// handleConn handles a single TLS connection: performs the link handshake as
// the responder, then runs the cell loop.
func (r *MockRelay) handleConn(conn net.Conn) {
	defer conn.Close()
	tlsConn := tls.Server(conn, r.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("testharness %s: tls handshake: %v", r.cfg.Nickname, err)
		return
	}
	// per tor-spec, cells sent before the link protocol is negotiated carry
	// 2-byte circuit IDs. The client's first VERSIONS arrives narrow; the
	// codec flips to the negotiated width in linkHandshake below (mirroring
	// channeltls.c:1620).
	codec := torcell.NewCodec(tlsConn, 2)
	if err := r.linkHandshake(codec); err != nil {
		log.Printf("testharness %s: link handshake: %v", r.cfg.Nickname, err)
		return
	}
	r.cellLoop(tlsConn, codec)
}

// linkHandshake performs the v3 link handshake as the responder.
func (r *MockRelay) linkHandshake(codec *torcell.Codec) error {
	// 1. Read client VERSIONS.
	vc, err := codec.ReadVarCell()
	if err != nil {
		return fmt.Errorf("read versions: %w", err)
	}
	if vc.Command != torcell.CellVersions {
		return fmt.Errorf("expected VERSIONS, got %d", vc.Command)
	}
	// Pick the highest version we support (we support 4 and 5).
	best := uint16(0)
	for i := 0; i+2 <= len(vc.Payload); i += 2 {
		v := binary.BigEndian.Uint16(vc.Payload[i:])
		if v == 4 || v == 5 {
			if v > best {
				best = v
			}
		}
	}
	if best == 0 {
		return errors.New("no common link protocol version")
	}

	// 2. Send our VERSIONS. The reply must go out with the same 2-byte
	// circuit-ID width the client is still using (it flips only after
	// reading our VERSIONS), so the width flip happens after the write —
	// mirroring C, which sets wide_circ_ids after sending the VERSIONS cell
	// (channeltls.c:1620 sets it after connection_or_send_versions).
	versionsPayload := []byte{0x00, byte(best)}
	if err := codec.WriteVarCell(&torcell.VarCell{Command: torcell.CellVersions, Payload: versionsPayload}); err != nil {
		return err
	}
	codec.SetCircIDWidth(4)

	// 3. Send CERTS (empty-ish: we send a minimal valid CERTS cell the client
	// will consume and ignore) and AUTH_CHALLENGE. The client's
	// consumeHandshakeCells drains these.
	if err := codec.WriteVarCell(&torcell.VarCell{Command: torcell.CellCerts, Payload: []byte{0x00, 0x00}}); err != nil {
		return err
	}
	authChallenge := make([]byte, 34) // 1 byte n_types + 2 bytes type + 32 bytes challenge
	authChallenge[0] = 1
	binary.BigEndian.PutUint16(authChallenge[1:3], 1) // AUTH_RSA_SHA256_TLSSECRET
	if err := codec.WriteVarCell(&torcell.VarCell{Command: torcell.CellAuthChallenge, Payload: authChallenge}); err != nil {
		return err
	}

	// 4. Send NETINFO.
	if err := r.sendNetinfo(codec); err != nil {
		return err
	}
	// 5. Read client NETINFO (it arrives after the client drains our
	// CERTS/AUTH_CHALLENGE). We read it with a short deadline.
	if err := r.readNetinfo(codec); err != nil {
		return err
	}
	return nil
}

func (r *MockRelay) sendNetinfo(codec *torcell.Codec) error {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(time.Now().Unix()))
	// Peer address (client). We don't know it precisely; write a placeholder
	// IPv4 0.0.0.0.
	buf.WriteByte(4)
	buf.WriteByte(4)
	buf.Write([]byte{0, 0, 0, 0})
	buf.WriteByte(0) // zero my-addresses
	cell := &torcell.Cell{Command: torcell.CellNetinfo}
	copy(cell.Payload[:], buf.Bytes())
	return codec.WriteCell(cell)
}

func (r *MockRelay) readNetinfo(codec *torcell.Codec) error {
	// The client sends NETINFO as a fixed cell. Read with ReadAny.
	msg, err := codec.ReadAny()
	if err != nil {
		return fmt.Errorf("read netinfo: %w", err)
	}
	if c, ok := msg.(*torcell.Cell); !ok || c.Command != torcell.CellNetinfo {
		return fmt.Errorf("expected NETINFO, got %T", msg)
	}
	return nil
}

// cellLoop reads cells and dispatches CREATE2 / RELAY / DESTROY.
func (r *MockRelay) cellLoop(conn net.Conn, codec *torcell.Codec) {
	for {
		msg, err := codec.ReadAny()
		if err != nil {
			return
		}
		cell, ok := msg.(*torcell.Cell)
		if !ok {
			continue
		}
		switch cell.Command {
		case torcell.CellCreate2:
			r.handleCreate2(codec, cell)
		case torcell.CellCreateFast:
			r.handleCreateFast(codec, cell)
		case torcell.CellRelay, torcell.CellRelayEarly:
			r.handleRelay(conn, codec, cell)
		case torcell.CellDestroy:
			r.handleDestroy(cell)
		case torcell.CellPadding:
			// ignore
		}
	}
}

// handleCreate2 processes a CREATE2: run the ntor server handshake, store the
// relay-crypto layer, and reply CREATED2.
func (r *MockRelay) handleCreate2(codec *torcell.Codec, cell *torcell.Cell) {
	payload := cell.Payload[:]
	if len(payload) < 4 {
		return
	}
	hsType := binary.BigEndian.Uint16(payload[0:2])
	hsLen := binary.BigEndian.Uint16(payload[2:4])
	if int(hsLen) > len(payload)-4 {
		return
	}
	hsData := payload[4 : 4+int(hsLen)]
	if hsType != 2 {
		r.sendDestroy(codec, cell.CircID, torcell.DestroyReasonBadProtocol)
		return
	}
	reply, keys, err := ntor.ServerHandshake(hsData, r.cfg.OnionKey, relaycrypto.TotalKeyLen)
	if err != nil {
		log.Printf("testharness %s: ntor server handshake: %v", r.cfg.Nickname, err)
		r.sendDestroy(codec, cell.CircID, torcell.DestroyReasonInternal)
		return
	}
	// Build the relay-crypto layer (reversed: the relay's forward = client's
	// backward). The first 72 bytes are the key material; the rest is KH.
	layer, err := relaycrypto.NewLayerReversed(keys[:relaycrypto.KeyMaterialLen])
	if err != nil {
		r.sendDestroy(codec, cell.CircID, torcell.DestroyReasonInternal)
		return
	}
	rc := &relayCircuit{
		circID:  cell.CircID,
		layer:   layer,
		streams: make(map[uint16]*relayStream),
	}
	r.mu.Lock()
	r.circuits[cell.CircID] = rc
	r.mu.Unlock()

	// CREATED2 payload: [handshake_len:2][handshake_data], mirroring
	// created_cell_format (onion.c: created_cell_parse reads handshake_len
	// from the first 2 bytes and the reply follows — there is no
	// handshake-type echo on replies). hsData is the 64-byte ntor reply.
	created2 := make([]byte, 2+len(reply))
	binary.BigEndian.PutUint16(created2[0:2], uint16(len(reply)))
	copy(created2[2:], reply)
	out := &torcell.Cell{CircID: cell.CircID, Command: torcell.CellCreated2}
	copy(out.Payload[:], created2)
	codec.WriteCell(out)
}

// handleCreateFast processes a CREATE_FAST: run the CREATE_FAST server
// handshake, store the relay-crypto layer, and reply CREATED_FAST. The
// onionskin is the raw 20-byte client nonce and the reply is the raw 40-byte
// y||H(x||y) (no type/length prefix), matching the client's
// buildFirstHopFast/finishFastHandshake.
func (r *MockRelay) handleCreateFast(codec *torcell.Codec, cell *torcell.Cell) {
	onionskin := cell.Payload[:fast.NonceLen]
	reply, keys, err := fast.ServerHandshake(onionskin, relaycrypto.TotalKeyLen)
	if err != nil {
		log.Printf("testharness %s: CREATE_FAST server handshake: %v", r.cfg.Nickname, err)
		r.sendDestroy(codec, cell.CircID, torcell.DestroyReasonInternal)
		return
	}
	// Reversed layer: the relay's forward = client's backward.
	layer, err := relaycrypto.NewLayerReversed(keys[:relaycrypto.KeyMaterialLen])
	if err != nil {
		r.sendDestroy(codec, cell.CircID, torcell.DestroyReasonInternal)
		return
	}
	rc := &relayCircuit{
		circID:  cell.CircID,
		layer:   layer,
		streams: make(map[uint16]*relayStream),
	}
	r.mu.Lock()
	r.circuits[cell.CircID] = rc
	r.mu.Unlock()

	out := &torcell.Cell{CircID: cell.CircID, Command: torcell.CellCreatedFast}
	copy(out.Payload[:], reply)
	codec.WriteCell(out)
}

// handleRelay processes a RELAY / RELAY_EARLY cell arriving on the wire. It
// peels this hop's AES layer and checks the digest; if recognized, it
// dispatches the relay command. If not recognized, the cell is destined for a
// further hop, so it forwards the once-peeled buffer down the in-process hop
// chain (each subsequent hop peels its own layer and checks again).
func (r *MockRelay) handleRelay(conn net.Conn, codec *torcell.Codec, cell *torcell.Cell) {
	r.mu.Lock()
	rc, ok := r.circuits[cell.CircID]
	r.mu.Unlock()
	if !ok {
		return
	}
	buf := make([]byte, len(cell.Payload))
	copy(buf, cell.Payload[:])
	r.dispatchForward(codec, rc, buf)
}

// dispatchForward peels rc's AES layer, checks the digest, and either
// dispatches the recognized relay command or forwards the peeled buffer to the
// next hop. This recurses down the chain until some hop recognizes the cell.
func (r *MockRelay) dispatchForward(codec *torcell.Codec, rc *relayCircuit, buf []byte) {
	if !rc.layer.RelayReceiveForward(buf) {
		// Not for this hop: forward the peeled buffer to the next hop.
		if rc.nextHop != nil {
			rc.nextRelay.dispatchForward(codec, rc.nextHop, buf)
		}
		return
	}
	parsed := torcell.ParseRelayCell(buf)
	switch parsed.Header.Command {
	case torcell.RelayExtend2:
		r.handleExtend2(codec, rc, parsed.Payload)
	case torcell.RelayBegin:
		r.handleBegin(codec, rc, parsed.Header.StreamID, parsed.Payload)
	case torcell.RelayData:
		r.handleData(codec, rc, parsed.Header.StreamID, parsed.Payload)
	case torcell.RelayEnd:
		r.handleEnd(rc, parsed.Header.StreamID)
	case torcell.RelaySendme, torcell.RelayDrop:
		// ignore
	}
}

// handleExtend2 processes an EXTEND2: parse link specifiers, find the next
// relay, send CREATE2, wrap CREATED2 as EXTENDED2 encrypted back to client.
//
// The link-specifier type codes are validated like trunnel's
// link_specifier_parse_into (src/trunnel/ed25519_cert.c): 0=LS_IPV4 (len 6),
// 1=LS_IPV6 (len 18), 2=LS_LEGACY_ID (len 20), 3=LS_ED25519_ID (len 32). A
// specifier whose declared length doesn't fit its type is a protocol
// violation and destroys the circuit with BadProtocol, the same way
// extend_cell_parse fails on the C side.
func (r *MockRelay) handleExtend2(codec *torcell.Codec, rc *relayCircuit, body []byte) {
	if len(body) < 1 {
		return
	}
	nSpecs := int(body[0])
	off := 1
	var nextID [20]byte
	for i := 0; i < nSpecs; i++ {
		if off+2 > len(body) {
			r.sendDestroy(codec, rc.circID, torcell.DestroyReasonBadProtocol)
			return
		}
		lsType := body[off]
		lsLen := int(body[off+1])
		off += 2
		if off+lsLen > len(body) {
			r.sendDestroy(codec, rc.circID, torcell.DestroyReasonBadProtocol)
			return
		}
		lsData := body[off : off+lsLen]
		off += lsLen
		switch lsType {
		case 0: // LS_IPV4: 4-byte address + 2-byte port
			if lsLen != 6 {
				r.sendDestroy(codec, rc.circID, torcell.DestroyReasonBadProtocol)
				return
			}
			// We route by identity digest, so the address is ignored.
		case 1: // LS_IPV6: 16-byte address + 2-byte port
			if lsLen != 18 {
				r.sendDestroy(codec, rc.circID, torcell.DestroyReasonBadProtocol)
				return
			}
		case 2: // LS_LEGACY_ID: RSA identity digest
			if lsLen != 20 {
				r.sendDestroy(codec, rc.circID, torcell.DestroyReasonBadProtocol)
				return
			}
			copy(nextID[:], lsData)
		case 3: // LS_ED25519_ID: ed25519 identity (not used for mock routing)
			if lsLen != 32 {
				r.sendDestroy(codec, rc.circID, torcell.DestroyReasonBadProtocol)
				return
			}
		default:
			// Unknown specifier types are ignored, per trunnel's default case.
		}
	}
	if off+4 > len(body) {
		r.sendDestroy(codec, rc.circID, torcell.DestroyReasonBadProtocol)
		return
	}
	hsType := binary.BigEndian.Uint16(body[off : off+2])
	hsLen := binary.BigEndian.Uint16(body[off+2 : off+4])
	off += 4
	if off+int(hsLen) > len(body) {
		r.sendDestroy(codec, rc.circID, torcell.DestroyReasonBadProtocol)
		return
	}
	hsData := body[off : off+int(hsLen)]
	if hsType != 2 {
		r.sendDestroy(codec, rc.circID, torcell.DestroyReasonBadProtocol)
		return
	}
	// Find the next relay by identity digest.
	next := r.nextHop(nextID)
	if next == nil {
		log.Printf("testharness %s: EXTEND2: no next hop for id %x", r.cfg.Nickname, nextID)
		return
	}
	// Dial the next relay over TLS and perform a link handshake + CREATE2.
	nextRC, err := next.extendTo(hsData, rc, r)
	if err != nil {
		log.Printf("testharness %s: EXTEND2: extend to %s failed: %v", r.cfg.Nickname, next.cfg.Nickname, err)
		return
	}
	// Link the chain: this hop's nextHop is the new circuit on the next relay.
	rc.nextHop = nextRC.circuit
	rc.nextRelay = next
	// nextRC holds the next relay's circuit + the CREATED2 reply data. We need
	// to wrap the reply as EXTENDED2 and encrypt it back to the client through
	// all hops from this one back to the guard.
	extended2Body := nextRC.created2Payload
	r.sendRelayBackward(codec, rc, 0, torcell.RelayExtended2, extended2Body)
}

// extendTo is called on the NEXT relay: it dials back to itself? No — the next
// relay is a separate MockRelay listening on its own port. But we are already
// that next relay (next == the MockRelay for the next hop). So we need to
// establish a TLS connection from THIS relay (the guard) to the next relay,
// perform a link handshake, and send CREATE2. However, that would make the
// guard a client to the next relay — which is exactly how Tor works (relays
// dial each other). But to keep the mock simple and avoid a second TLS layer,
// we instead handle the extension *in-process*: the next relay performs the
// ntor server handshake directly and returns the CREATED2 payload, and we
// chain the crypto layers in memory.
//
// This is a valid simplification: the on-wire format between relays is the
// same CREATE2/CREATED2, and the crypto is the same. Doing it in-process just
// removes the TLS hop between relays while exercising identical handshake and
// crypto code. The client still sees a real multi-hop circuit with real
// per-hop keys.
func (r *MockRelay) extendTo(hsData []byte, prev *relayCircuit, prevRelay *MockRelay) (*extendResult, error) {
	reply, keys, err := ntor.ServerHandshake(hsData, r.cfg.OnionKey, relaycrypto.TotalKeyLen)
	if err != nil {
		return nil, err
	}
	layer, err := relaycrypto.NewLayerReversed(keys[:relaycrypto.KeyMaterialLen])
	if err != nil {
		return nil, err
	}
	// Allocate a circuit ID on this relay. We use a deterministic one derived
	// from the prev circuit to avoid collisions.
	r.mu.Lock()
	var circID uint32 = 1
	for {
		if _, ok := r.circuits[circID]; !ok {
			break
		}
		circID++
	}
	rc := &relayCircuit{
		circID:    circID,
		layer:     layer,
		prevHop:   prev,
		prevRelay: prevRelay,
		streams:   make(map[uint16]*relayStream),
	}
	r.circuits[circID] = rc
	r.mu.Unlock()

	// CREATED2 reply framed as [handshake_len:2][handshake_data] (same rule
	// as the guard's handleCreate2; the type field is not echoed).
	created2 := make([]byte, 2+len(reply))
	binary.BigEndian.PutUint16(created2[0:2], uint16(len(reply)))
	copy(created2[2:], reply)
	return &extendResult{circuit: rc, created2Payload: created2}, nil
}

// extendResult carries the new circuit and the CREATED2 payload to wrap.
type extendResult struct {
	circuit         *relayCircuit
	created2Payload []byte
}

// handleBegin processes a RELAY_BEGIN: dial the target, reply CONNECTED, and
// start piping data. Only the exit relay does this (it has no prevHop that
// would forward further).
func (r *MockRelay) handleBegin(codec *torcell.Codec, rc *relayCircuit, streamID uint16, payload []byte) {
	// payload is "host:port\0" optionally followed by a 4-byte flags field.
	// The target is everything up to the first NUL; the flags (if any) are
	// ignored by the exit beyond IPv4/IPv6 reachability, which the mock does
	// not enforce.
	target := beginTarget(payload)
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.Dial("tcp", target)
	if err != nil {
		log.Printf("testharness %s: BEGIN dial %s: %v", r.cfg.Nickname, target, err)
		// Send RELAY_END with reason 4 (CONNECTREFUSED).
		r.sendRelayBackward(codec, rc, streamID, torcell.RelayEnd, []byte{4})
		return
	}
	rc.mu.Lock()
	rc.streams[streamID] = &relayStream{conn: conn, circ: rc, streamID: streamID}
	rc.mu.Unlock()
	// Send RELAY_CONNECTED with the bound IPv4 address (4 bytes, big-endian)
	// and a zero TTL, matching connected_cell_format. We report the actual
	// dialed address so the client's parseConnected has a real value.
	connected := connectedPayload(conn.LocalAddr())
	r.sendRelayBackward(codec, rc, streamID, torcell.RelayConnected, connected)
	// Start reading from the target and sending RELAY_DATA back.
	go r.pipeFromTarget(codec, rc, streamID, conn)
}

// beginTarget extracts the "host:port" target from a RELAY_BEGIN payload,
// which is "host:port\0" optionally followed by a 4-byte flags field. It
// returns the bytes up to the first NUL.
func beginTarget(payload []byte) string {
	for i, b := range payload {
		if b == 0 {
			return string(payload[:i])
		}
	}
	return string(payload)
}

// connectedPayload builds a RELAY_CONNECTED payload for the given local
// address: a 4-byte big-endian IPv4 address followed by a 4-byte zero TTL.
// For a non-IPv4 address it returns a zero IPv4 address (the client treats
// an all-zero first word as "no address").
func connectedPayload(localAddr net.Addr) []byte {
	host, _, _ := net.SplitHostPort(localAddr.String())
	ip := net.ParseIP(host)
	if v4 := ip.To4(); v4 != nil {
		return []byte{v4[0], v4[1], v4[2], v4[3], 0, 0, 0, 0}
	}
	return []byte{0, 0, 0, 0, 0, 0, 0, 0}
}

// pipeFromTarget reads from the target TCP connection and sends RELAY_DATA
// cells back to the client through the circuit's backward layer.
func (r *MockRelay) pipeFromTarget(codec *torcell.Codec, rc *relayCircuit, streamID uint16, conn net.Conn) {
	buf := make([]byte, torcell.RelayPayloadSizeMax)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			r.sendRelayBackward(codec, rc, streamID, torcell.RelayData, buf[:n])
		}
		if err != nil {
			// Send END with reason DONE (6) for a normal close and clean up.
			// (Reason 1 is MISC, not DONE; the client maps DONE to EOF.)
			r.sendRelayBackward(codec, rc, streamID, torcell.RelayEnd, []byte{6})
			rc.mu.Lock()
			delete(rc.streams, streamID)
			rc.mu.Unlock()
			conn.Close()
			return
		}
	}
}

// handleData processes a RELAY_DATA: write to the target stream.
func (r *MockRelay) handleData(codec *torcell.Codec, rc *relayCircuit, streamID uint16, payload []byte) {
	rc.mu.Lock()
	s, ok := rc.streams[streamID]
	rc.mu.Unlock()
	if !ok {
		return
	}
	s.conn.Write(payload)
}

// handleEnd processes a RELAY_END: close the target stream.
func (r *MockRelay) handleEnd(rc *relayCircuit, streamID uint16) {
	rc.mu.Lock()
	s, ok := rc.streams[streamID]
	if ok {
		delete(rc.streams, streamID)
	}
	rc.mu.Unlock()
	if ok {
		s.conn.Close()
	}
}

// sendRelayBackward builds a relay cell, encrypts it backward through this
// hop's layer (and any prev hops), and sends it to the client.
//
// For a multi-hop circuit, a cell from the exit must be encrypted by the
// exit's backward layer, then by the middle's backward layer, then by the
// guard's backward layer. In our in-process model, each relay only has its own
// layer; to encrypt through all hops, we walk the prevHop chain: the exit
// stamps+encrypts, then each prev hop adds its backward AES layer (no digest
// stamping, since the exit already stamped). The guard then sends the cell on
// the wire.
func (r *MockRelay) sendRelayBackward(codec *torcell.Codec, rc *relayCircuit, streamID uint16, cmd uint8, payload []byte) {
	cellPayload := torcell.BuildRelayCell(cmd, streamID, payload)
	// Stamp + encrypt at the originating hop (the exit / this hop).
	rc.layer.RelaySendBackward(cellPayload[:])
	// Walk backward through prev hops, adding their backward AES layer.
	// prevRelay/prevHop chain: rc.prevHop is the hop before us. But the
	// backward encryption must be applied by each relay in the chain from the
	// exit back to the guard. Since we did extension in-process, the chain is:
	//   guard (rc if rc.prevHop == nil) <- middle <- exit
	// The exit's sendRelayBackward is called; it must then apply the middle's
	// backward layer and the guard's backward layer. We walk via prevHop.
	cur := rc.prevHop
	for cur != nil {
		cur.layer.RelaySendBackwardOnly(cellPayload[:])
		cur = cur.prevHop
	}
	out := &torcell.Cell{CircID: rc.topCircID(), Command: torcell.CellRelay}
	copy(out.Payload[:], cellPayload[:])
	if err := codec.WriteCell(out); err != nil {
		log.Printf("testharness %s: sendRelayBackward write: %v", r.cfg.Nickname, err)
	}
}

// topCircID returns the circuit ID on the guard (the client-facing link).
func (rc *relayCircuit) topCircID() uint32 {
	cur := rc
	for cur.prevHop != nil {
		cur = cur.prevHop
	}
	return cur.circID
}

// handleDestroy removes a circuit.
func (r *MockRelay) handleDestroy(cell *torcell.Cell) {
	r.mu.Lock()
	rc, ok := r.circuits[cell.CircID]
	if ok {
		delete(r.circuits, cell.CircID)
	}
	r.mu.Unlock()
	if ok {
		rc.mu.Lock()
		for _, s := range rc.streams {
			s.conn.Close()
		}
		rc.streams = nil
		rc.mu.Unlock()
	}
}

func (r *MockRelay) sendDestroy(codec *torcell.Codec, circID uint32, reason uint8) {
	out := &torcell.Cell{CircID: circID, Command: torcell.CellDestroy}
	out.Payload[0] = reason
	codec.WriteCell(out)
}

// Harness owns a chain of mock relays and the directory the client uses. It
// wires up next-hop resolution so EXTEND2 can find the next relay.
type Harness struct {
	Relays []*MockRelay
	// Dir is the directory.Router map the client uses. Built from the relays.
	Dir map[string]*dirEntry
}

// dirEntry is a minimal directory entry exposed to the client. We avoid
// importing the directory package (which would create a test-only dependency
// from a non-test package); instead the test that builds the client converts
// these to directory.Router values.
type dirEntry struct {
	Nickname string
	IDDigest [20]byte
	OnionKey [32]byte
	Address  string
	Flags    []string
}

// NewHarness starts a chain of n mock relays (guard, middle, ..., exit) on
// ephemeral loopback ports and returns a Harness. The relays' identity
// digests are derived from their generated TLS certs (so the client's
// verifyPeer passes), and their onion keys are freshly generated.
func NewHarness(n int) (*Harness, error) {
	if n < 1 {
		return nil, errors.New("testharness: need at least 1 relay")
	}
	h := &Harness{Dir: make(map[string]*dirEntry)}
	roles := func(i, n int) []string {
		flags := []string{"Fast", "Stable", "Valid"}
		if i == 0 {
			flags = append([]string{"Guard"}, flags...)
		}
		if i == n-1 {
			flags = append([]string{"Exit"}, flags...)
		}
		return flags
	}
	for i := 0; i < n; i++ {
		nickname := fmt.Sprintf("mockrelay%d", i)
		kp, err := ntor.GenerateServerKeyPair([20]byte{}) // routerID filled below
		if err != nil {
			h.Close()
			return nil, err
		}
		cfg := RelayConfig{
			Nickname:   nickname,
			OnionKey:   kp,
			ListenAddr: "127.0.0.1:0",
		}
		relay, err := NewMockRelay(cfg)
		if err != nil {
			h.Close()
			return nil, err
		}
		// Derive the real identity digest from the cert and update the keypair.
		id := relay.IdentityDigest()
		relay.cfg.IDDigest = id
		relay.cfg.OnionKey.RouterID = id
		h.Relays = append(h.Relays, relay)
		h.Dir[nickname] = &dirEntry{
			Nickname: nickname,
			IDDigest: id,
			OnionKey: relay.OnionPublicKey(),
			Address:  relay.Addr(),
			Flags:    roles(i, n),
		}
	}
	// Wire next-hop resolution: a relay resolves an identity digest to the
	// MockRelay with that digest.
	resolve := func(id [20]byte) *MockRelay {
		for _, rl := range h.Relays {
			if rl.cfg.IDDigest == id {
				return rl
			}
		}
		return nil
	}
	for _, rl := range h.Relays {
		rl.SetNextHopResolver(resolve)
	}
	// Start serving.
	for _, rl := range h.Relays {
		go rl.Serve()
	}
	return h, nil
}

// Close stops all relays.
func (h *Harness) Close() {
	for _, rl := range h.Relays {
		rl.Close()
	}
}

// GuardEntry returns the directory entry for the guard (first relay).
func (h *Harness) GuardEntry() *dirEntry {
	if len(h.Relays) == 0 {
		return nil
	}
	return h.Dir[h.Relays[0].cfg.Nickname]
}

// AllEntries returns all directory entries in path order.
func (h *Harness) AllEntries() []*dirEntry {
	out := make([]*dirEntry, 0, len(h.Relays))
	for _, rl := range h.Relays {
		out = append(out, h.Dir[rl.cfg.Nickname])
	}
	return out
}

// Ensure unused imports are referenced in non-test builds.
var (
	_ = context.Background
	_ = io.EOF
)
