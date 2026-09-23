// Package socks5 implements a SOCKS5 (RFC 1928) proxy server that routes
// CONNECT requests through Tor circuits provided by a Dialer. It is the
// client-facing entry point of the Go Tor client: applications configure
// their SOCKS5 proxy to this listener and their traffic is tunneled through
// the Tor network.
//
// This mirrors src/core/proto/proto_socks.c in the C reference
// implementation, restricted to the SOCKS5 CONNECT method with no
// authentication (the common client configuration).
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
	"sync"
	"time"

	"github.com/proxy/tor-go/internal/circuit"
)

// requestTimeout is the default deadline for opening a Tor stream.
const requestTimeout = 120 * time.Second

// SOCKS5 protocol constants (RFC 1928).
const (
	socksVersion  = 0x05
	authNone      = 0x00
	authNoAccept  = 0xFF
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04

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

// Dialer opens a bidirectional stream to target through Tor. It is
// implemented by *torclient.Client.
type Dialer interface {
	// DialStream returns an io.ReadWriteCloser connected to target
	// (host:port) over a Tor circuit.
	DialStream(ctx context.Context, target string) (io.ReadWriteCloser, error)
}

// Server is a SOCKS5 proxy server.
type Server struct {
	dialer Dialer
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
	// We support no-auth only. If the client offered it, select it; else fail.
	offeredNone := false
	for i := 0; i < nmethods; i++ {
		if br.buf[i] == authNone {
			offeredNone = true
			break
		}
	}
	if !offeredNone {
		conn.Write([]byte{socksVersion, authNoAccept})
		return
	}
	if _, err := conn.Write([]byte{socksVersion, authNone}); err != nil {
		return
	}

	// 2. Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
	if err := br.readFull(4); err != nil {
		return
	}
	if br.buf[0] != socksVersion {
		return
	}
	cmd := br.buf[1]
	atyp := br.buf[3]
	if cmd != cmdConnect {
		reply(conn, repCmdNotSupported, nil, 0)
		return
	}

	host, port, err := readAddr(br, atyp)
	if err != nil {
		reply(conn, repAddrNotSupported, nil, 0)
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	log.Printf("socks5: CONNECT %s", target)

	// 3. Open a Tor stream.
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	stream, err := s.dialer.DialStream(ctx, target)
	if err != nil {
		log.Printf("socks5: dial %s failed: %v", target, err)
		reply(conn, mapErrToRep(err), nil, 0)
		return
	}
	defer stream.Close()

	// 4. Reply success. Bind address is 0.0.0.0:0.
	if err := reply(conn, repSuccess, net.IPv4zero, 0); err != nil {
		return
	}

	// 5. Pipe bidirectionally.
	pipe(conn, stream)
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

// reply writes a SOCKS5 reply.
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
