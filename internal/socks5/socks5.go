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

	"github.com/proxy/tor-go/internal/circuit"
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
	if isOnionHost(host) {
		log.Printf("socks5: refusing .onion target %s (hidden services unsupported)", target)
		reply(conn, repCmdNotSupported, nil, 0)
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

// isOnionHost reports whether host is a .onion hidden-service address (case-
// insensitive, matching the standard v2/v3 suffix).
func isOnionHost(host string) bool {
	return strings.HasSuffix(strings.ToLower(host), ".onion")
}

// handleResolve performs a SOCKS5 RESOLVE (Tor extension): resolve hostname
// through the Tor exit and reply with the address.
func (s *Server) handleResolve(ctx context.Context, conn net.Conn, host string) {
	log.Printf("socks5: RESOLVE %s", host)
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
