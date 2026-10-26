// Package socks5 implements a SOCKS5 (RFC 1928) proxy server that routes
// CONNECT requests through Tor circuits provided by a Dialer. It is the
// client-facing entry point of the Go Tor client: applications configure
// their SOCKS5 proxy to this listener and their traffic is tunneled through
// the Tor network.
//
// This mirrors src/core/proto/proto_socks.c in the C reference
// implementation. It supports the SOCKS5 CONNECT, RESOLVE and RESOLVE_PTR
// commands with no-auth (0x00) and username/password (0x02, RFC 1929)
// authentication methods.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goose-network/tor-go/internal/circuit"
)

// requestTimeout is the default deadline for opening a Tor stream.
const requestTimeout = 120 * time.Second

// SOCKS5 protocol constants (RFC 1928 / RFC 1929).
const (
	socksVersion = 0x05
	authNone     = 0x00
	authUserPass = 0x02
	authNoAccept = 0xFF

	cmdConnect    = 0x01
	cmdBind       = 0x02
	cmdResolve    = 0xF0 // Tor extension: RESOLVE (hostname -> A/AAAA)
	cmdResolvePtr = 0xF1 // Tor extension: RESOLVE_PTR (address -> PTR)

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repNotAllowed       = 0x02
	repNetUnreachable   = 0x03
	repHostUnreachable  = 0x04
	repConnRefused      = 0x05
	repTTLExpired       = 0x06
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08
)

// Dialer opens bidirectional streams and performs DNS resolution through
// Tor. It is implemented by *torclient.Client.
type Dialer interface {
	// DialStream returns an io.ReadWriteCloser connected to target
	// (host:port) over a Tor circuit.
	DialStream(ctx context.Context, target string) (io.ReadWriteCloser, error)
	// Resolve performs a hostname lookup through the Tor exit, returning the
	// first resolved address. It is used by the SOCKS5 RESOLVE command.
	Resolve(ctx context.Context, hostname string) (string, error)
	// ResolvePtr performs a reverse DNS lookup through the Tor exit, returning
	// the PTR hostname for the given IP. It is used by RESOLVE_PTR.
	ResolvePtr(ctx context.Context, ip string) (string, error)
}

// AuthConfig configures SOCKS5 authentication. If a Username/Password is set,
// the server requires RFC 1929 username/password auth and rejects clients that
// don't match. If empty, only no-auth is offered.
type AuthConfig struct {
	Username string
	Password string
}

// Server is a SOCKS5 proxy server.
type Server struct {
	dialer Dialer
	auth   AuthConfig
	addr   string
	ln     net.Listener
	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool

	// RejectPrivateAddresses, when set, refuses CONNECT/RESOLVE/RESOLVE_PTR
	// targets that are private, loopback, or link-local addresses (and the
	// "localhost"/"*.local" hostnames), mirroring the C client's
	// ClientRejectInternalAddresses (connection_edge.c:2380). This prevents
	// a misconfigured application from tunneling to a private address
	// through Tor. Off by default so loopback test targets and explicit
	// private destinations are still allowed; the real client enables it.
	RejectPrivateAddresses bool
}

// New returns a SOCKS5 server bound to addr that routes through dialer.
func New(addr string, dialer Dialer) *Server {
	return &Server{addr: addr, dialer: dialer}
}

// NewWithAuth returns a SOCKS5 server that requires the given username/password
// (RFC 1929) from connecting clients. If auth is empty, behaves like New.
func NewWithAuth(addr string, dialer Dialer, auth AuthConfig) *Server {
	return &Server{addr: addr, dialer: dialer, auth: auth}
}

// ListenAndServe binds the listener and serves SOCKS5 connections until
// Shutdown is called.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("socks5: listen %s: %w", s.addr, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	log.Printf("socks5: listening on %s", s.addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("socks5: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// Addr returns the listener address (after ListenAndServe binds).
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Shutdown stops accepting connections and waits for in-flight handlers to
// finish.
func (s *Server) Shutdown() error {
	s.mu.Lock()
	s.closed = true
	if s.ln != nil {
		s.ln.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

// handle services a single SOCKS5 client connection.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	br := newBufConn(conn)

	// 1. Greeting: VER, NMETHODS, METHODS.
	if err := br.readFull(2); err != nil {
		return
	}
	if br.buf[0] != socksVersion {
		return
	}
	nmethods := int(br.buf[1])
	if err := br.readFull(nmethods); err != nil {
		return
	}
	offeredNone := false
	offeredUserPass := false
	for i := 0; i < nmethods; i++ {
		switch br.buf[i] {
		case authNone:
			offeredNone = true
		case authUserPass:
			offeredUserPass = true
		}
	}

	requireAuth := s.auth.Username != "" || s.auth.Password != ""
	var selectedMethod byte
	switch {
	case requireAuth && offeredUserPass:
		selectedMethod = authUserPass
	case offeredNone:
		selectedMethod = authNone
	case offeredUserPass:
		// We accept userpass even when not required (some clients prefer it).
		selectedMethod = authUserPass
	default:
		conn.Write([]byte{socksVersion, authNoAccept})
		return
	}
	if _, err := conn.Write([]byte{socksVersion, selectedMethod}); err != nil {
		return
	}

	// 2. If userpass was selected, perform the RFC 1929 sub-negotiation.
	if selectedMethod == authUserPass {
		if err := s.handleUserPass(conn, br); err != nil {
			log.Printf("socks5: userpass auth failed: %v", err)
			return
		}
	}

	// 3. Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
	if err := br.readFull(4); err != nil {
		return
	}
	if br.buf[0] != socksVersion {
		return
	}
	cmd := br.buf[1]
	atyp := br.buf[3]

	host, port, err := readAddr(br, atyp)
	if err != nil {
		reply(conn, repAddrNotSupported, nil, 0)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	switch cmd {
	case cmdConnect:
		s.handleConnect(ctx, conn, host, port)
	case cmdResolve:
		s.handleResolve(ctx, conn, host)
	case cmdResolvePtr:
		s.handleResolvePtr(ctx, conn, host)
	case cmdBind:
		reply(conn, repCmdNotSupported, nil, 0)
	default:
		reply(conn, repCmdNotSupported, nil, 0)
	}
}

// handleUserPass performs the RFC 1929 username/password sub-negotiation.
// Format: VER(1)=0x01, ULEN(1), UNAME, PLEN(1), PASSWD. Reply: VER(1)=0x01,
// STATUS(1) (0x00 = success).
func (s *Server) handleUserPass(conn net.Conn, br *bufConn) error {
	if err := br.readFull(1); err != nil {
		return err
	}
	if br.buf[0] != 0x01 {
		return errors.New("socks5: bad userpass version")
	}
	if err := br.readFull(1); err != nil {
		return err
	}
	ulen := int(br.buf[0])
	if ulen > 255 {
		return errors.New("socks5: username too long")
	}
	if err := br.readFull(ulen); err != nil {
		return err
	}
	username := string(br.buf[:ulen])
	if err := br.readFull(1); err != nil {
		return err
	}
	plen := int(br.buf[0])
	if err := br.readFull(plen); err != nil {
		return err
	}
	password := string(br.buf[:plen])

	if s.auth.Username != "" && username != s.auth.Username {
		conn.Write([]byte{0x01, 0x01})
		return errors.New("socks5: username mismatch")
	}
	if s.auth.Password != "" && password != s.auth.Password {
		conn.Write([]byte{0x01, 0x01})
		return errors.New("socks5: password mismatch")
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return err
	}
	return nil
}

// handleConnect opens a Tor stream to host:port and pipes bidirectionally.
func (s *Server) handleConnect(ctx context.Context, conn net.Conn, host string, port uint16) {
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	log.Printf("socks5: CONNECT %s", target)

	// Hidden-service (.onion) targets require the client-side hidden-service
	// subsystem (introduction-point / rendezvous circuits), which this client
	// does not implement. Refuse them explicitly with "command not supported"
	// rather than sending them to a normal exit, which cannot resolve .onion.
	if IsOnionHost(host) {
		log.Printf("socks5: refusing .onion target %s (hidden services unsupported)", target)
		reply(conn, repCmdNotSupported, nil, 0)
		return
	}

	// Refuse connections to port 0 (connection_edge.c: "Application asked to
	// connect to port 0. Refusing.").
	if port == 0 {
		log.Printf("socks5: refusing CONNECT to port 0")
		reply(conn, repNotAllowed, nil, 0)
		return
	}

	// Reject private/loopback/link-local destinations, mirroring the C
	// client's ClientRejectInternalAddresses check (connection_edge.c:2380).
	// Without a chosen exit, connecting to a private address is almost
	// certainly a misconfiguration (or a loop), so we fail it at the SOCKS
	// layer rather than tunneling it through Tor. Hostnames that are IP
	// literals are checked directly; "localhost"/"local"/"*.local" are
	// rejected too (tor_addr_hostname_is_local). Non-IP hostnames are
	// allowed (the exit resolves them and applies its own exit policy).
	// Gated on RejectPrivateAddresses (off by default; the real client
	// enables it) so loopback test targets still work.
	if s.RejectPrivateAddresses && RejectPrivateTarget(host) {
		log.Printf("socks5: refusing private/local target %s", target)
		reply(conn, repNotAllowed, nil, 0)
		return
	}

	stream, err := s.dialer.DialStream(ctx, target)
	if err != nil {
		log.Printf("socks5: dial %s failed: %v", target, err)
		reply(conn, mapErrToRep(err), nil, 0)
		return
	}
	defer stream.Close()

	// Reply success. Bind address is 0.0.0.0:0.
	if err := reply(conn, repSuccess, net.IPv4zero, 0); err != nil {
		return
	}
	pipe(conn, stream)
}

// IsOnionHost reports whether host is a .onion hidden-service address (case-
// insensitive, matching the standard v2/v3 suffix).
//
// Exported for the in-process dial path: torclient callers that dial streams
// directly (rather than through a SOCKS client) apply the same target policy
// the SOCKS server does.
func IsOnionHost(host string) bool {
	return strings.HasSuffix(strings.ToLower(host), ".onion")
}

// RejectPrivateTarget reports whether a CONNECT/RESOLVE target should be
// refused at the SOCKS layer as a private or local address. It mirrors the
// C client's ClientRejectInternalAddresses path (connection_edge.c:2380):
// the "localhost"/"local"/"*.local" hostnames (tor_addr_hostname_is_local)
// and any IP literal that tor_addr_is_internal_ considers internal. A
// non-IP hostname is allowed (the exit resolves it and enforces its exit
// policy). Returns false for an empty host (handled elsewhere).
//
// Exported for the same reason as IsOnionHost: the in-process dial path
// enforces the same policy the SOCKS server does.
func RejectPrivateTarget(host string) bool {
	if host == "" {
		return false
	}
	// Hostname-form local addresses.
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "local" || strings.HasSuffix(lower, ".local") {
		return true
	}
	// IP literal?
	ip := net.ParseIP(host)
	if ip == nil {
		return false // hostname: let the exit resolve and apply policy
	}
	return isInternalIP(ip)
}

// isInternalIP reports whether ip is an internal (private/loopback/link-
// local) address, mirroring tor_addr_is_internal_ (address.c:255) with
// for_listening=0. IPv4 rules: 0/8, 10/8, 127/8, 100.64/10, 169.254/16,
// 172.16/12, 192.168/16. IPv6 rules: fc00/7 (RFC 4193), fe80/10 and
// fec0/10 (link-local / deprecated site-local), and ::/127 (loopback).
// IPv4-mapped IPv6 addresses are reduced to their IPv4 form first.
func isInternalIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		// Treat as IPv4 (also covers IPv4-mapped IPv6).
		o0, o1 := v4[0], v4[1]
		switch {
		case o0 == 0, // 0/8
			o0 == 10,                           // 10/8
			o0 == 127,                          // 127/8
			o0 == 100 && o1 >= 64 && o1 <= 127, // 100.64/10
			o0 == 169 && o1 == 254,             // 169.254/16
			o0 == 172 && o1 >= 16 && o1 <= 31,  // 172.16/12
			o0 == 192 && o1 == 168:             // 192.168/16
			return true
		}
		return false
	}
	v6 := ip.To16()
	if v6 == nil {
		return true // unknown family: treat as unsafe (matches C fallback)
	}
	// IPv6 (not v4-mapped). Compare on the first 32-bit word.
	w0 := uint32(v6[0])<<24 | uint32(v6[1])<<16 | uint32(v6[2])<<8 | uint32(v6[3])
	// fc00/7  -> (w0 & 0xfe000000) == 0xfc000000
	if (w0 & 0xfe000000) == 0xfc000000 {
		return true
	}
	// fe80/10 -> (w0 & 0xffc00000) == 0xfe800000
	if (w0 & 0xffc00000) == 0xfe800000 {
		return true
	}
	// fec0/10 -> (w0 & 0xffc00000) == 0xfec00000
	if (w0 & 0xffc00000) == 0xfec00000 {
		return true
	}
	// ::/127 loopback: all-zero except the last bit.
	if w0 == 0 && v6[4] == 0 && v6[5] == 0 && v6[6] == 0 && v6[7] == 0 &&
		v6[8] == 0 && v6[9] == 0 && v6[10] == 0 && v6[11] == 0 &&
		v6[12] == 0 && v6[13] == 0 && v6[14] == 0 && v6[15] <= 1 {
		return true
	}
	return false
}

// handleResolve performs a SOCKS5 RESOLVE (Tor extension): resolve hostname
// through the Tor exit and reply with the address.
func (s *Server) handleResolve(ctx context.Context, conn net.Conn, host string) {
	log.Printf("socks5: RESOLVE %s", host)
	if s.RejectPrivateAddresses && RejectPrivateTarget(host) {
		log.Printf("socks5: refusing RESOLVE of private/local target %s", host)
		reply(conn, repNotAllowed, nil, 0)
		return
	}
	addr, err := s.dialer.Resolve(ctx, host)
	if err != nil {
		log.Printf("socks5: resolve %s failed: %v", host, err)
		reply(conn, mapErrToRep(err), nil, 0)
		return
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		reply(conn, repGeneralFailure, nil, 0)
		return
	}
	reply(conn, repSuccess, ip, 0)
}

// handleResolvePtr performs a SOCKS5 RESOLVE_PTR (Tor extension): reverse
// resolve an IP to a hostname through the Tor exit.
func (s *Server) handleResolvePtr(ctx context.Context, conn net.Conn, host string) {
	log.Printf("socks5: RESOLVE_PTR %s", host)
	if s.RejectPrivateAddresses && RejectPrivateTarget(host) {
		log.Printf("socks5: refusing RESOLVE_PTR of private/local target %s", host)
		reply(conn, repNotAllowed, nil, 0)
		return
	}
	name, err := s.dialer.ResolvePtr(ctx, host)
	if err != nil {
		log.Printf("socks5: resolve_ptr %s failed: %v", host, err)
		reply(conn, mapErrToRep(err), nil, 0)
		return
	}
	// Reply with the hostname in the domain address type.
	replyDomain(conn, repSuccess, name)
}

// readAddr reads the DST.ADDR field given the address type.
func readAddr(br *bufConn, atyp byte) (host string, port uint16, err error) {
	switch atyp {
	case atypIPv4:
		if err = br.readFull(4); err != nil {
			return
		}
		host = net.IP(br.buf[0:4]).String()
	case atypIPv6:
		if err = br.readFull(16); err != nil {
			return
		}
		host = net.IP(append([]byte(nil), br.buf[0:16]...)).String()
	case atypDomain:
		if err = br.readFull(1); err != nil {
			return
		}
		l := int(br.buf[0])
		if err = br.readFull(l); err != nil {
			return
		}
		host = string(br.buf[0:l])
	default:
		err = errors.New("socks5: unsupported ATYP")
		return
	}
	if err = br.readFull(2); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(br.buf[0:2])
	return
}

// reply writes a SOCKS5 reply with an IP bind address.
func reply(conn net.Conn, rep byte, bindIP net.IP, bindPort uint16) error {
	var atyp byte
	var addr []byte
	if v4 := bindIP.To4(); v4 != nil {
		atyp = atypIPv4
		addr = v4
	} else if bindIP != nil {
		atyp = atypIPv6
		addr = bindIP.To16()
	} else {
		atyp = atypIPv4
		addr = net.IPv4zero.To4()
	}
	out := []byte{socksVersion, rep, 0x00, atyp}
	out = append(out, addr...)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, bindPort)
	out = append(out, b...)
	_, err := conn.Write(out)
	return err
}

// replyDomain writes a SOCKS5 reply carrying a domain-name bind address
// (used for RESOLVE_PTR, where the result is a hostname).
func replyDomain(conn net.Conn, rep byte, name string) error {
	if len(name) > 255 {
		name = name[:255]
	}
	out := []byte{socksVersion, rep, 0x00, atypDomain, byte(len(name))}
	out = append(out, []byte(name)...)
	out = append(out, 0x00, 0x00) // bind port 0
	_, err := conn.Write(out)
	return err
}

// mapErrToRep maps a Dialer error to a SOCKS5 reply code.
func mapErrToRep(err error) byte {
	switch {
	case errors.Is(err, circuit.ErrConnRefused):
		return repConnRefused
	case errors.Is(err, circuit.ErrHostUnreachable):
		return repHostUnreachable
	case errors.Is(err, circuit.ErrNetUnreachable):
		return repNetUnreachable
	case errors.Is(err, context.DeadlineExceeded):
		return repTTLExpired
	default:
		return repGeneralFailure
	}
}

// pipe copies data bidirectionally between a and b until one side closes.
func pipe(a net.Conn, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
	// Closing b (the Tor stream) will unblock the other copy; closing a
	// (the client conn) does the same for the first.
	a.Close()
	b.Close()
	<-done
}

// bufConn is a helper that reads exact-length frames into a reusable buffer.
type bufConn struct {
	c   net.Conn
	buf []byte
}

func newBufConn(c net.Conn) *bufConn { return &bufConn{c: c, buf: make([]byte, 256)} }

func (b *bufConn) readFull(n int) error {
	if n > len(b.buf) {
		b.buf = make([]byte, n)
	}
	b.buf = b.buf[:n]
	_, err := io.ReadFull(b.c, b.buf)
	return err
}
