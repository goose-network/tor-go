// Package proxy implements outbound connection helpers that dial through an
// upstream proxy. The Tor client uses this to reach guard relays when it sits
// behind a SOCKS5 proxy (e.g. a local Clash/V2Ray instance at
// socks5://127.0.0.1:7890): the link layer's TCP connection to the relay is
// established through the upstream proxy before TLS and the Tor link handshake
// are layered on top.
//
// This mirrors the "ClientTransportPlugin" / SOCKS proxy support in
// src/core/or/connection_or.c and src/lib/transports/socks5.c of the C
// reference implementation, restricted to SOCKS5 with no authentication.
package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socksVersion = 0x05
	authNone     = 0x00
	cmdConnect   = 0x01
	atypIPv4     = 0x01
	atypDomain   = 0x03
	atypIPv6     = 0x04
	repSuccess   = 0x00
)

// Dial connects to target (host:port) by first establishing a TCP connection
// to the SOCKS5 proxy at proxyAddr and performing a SOCKS5 CONNECT. It returns
// the resulting stream, which a caller can then layer TLS on top of. If
// proxyAddr is empty, Dial dials target directly (no proxy).
func Dial(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	if proxyAddr == "" {
		d := &net.Dialer{}
		return d.DialContext(ctx, "tcp", target)
	}
	return dialSOCKS5(ctx, proxyAddr, target)
}

// dialSOCKS5 connects to proxyAddr, performs the SOCKS5 no-auth greeting and a
// CONNECT to target, and returns the tunneled connection.
func dialSOCKS5(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}

	d := &net.Dialer{Timeout: time.Until(deadline)}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy: dial socks5 %s: %w", proxyAddr, err)
	}
	conn.SetDeadline(deadline)

	// Greeting: VER, NMETHODS=1, METHOD=0x00 (no-auth).
	if _, err := conn.Write([]byte{socksVersion, 0x01, authNone}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: socks5 greeting: %w", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: socks5 greeting reply: %w", err)
	}
	// Request: VER, CMD=CONNECT, RSV, ATYP, DST.ADDR, DST.PORT.
	req, err := buildRequest(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: socks5 request: %w", err)
	}
	// Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: socks5 reply: %w", err)
	}
	if hdr[1] != repSuccess {
		conn.Close()
		return nil, fmt.Errorf("proxy: socks5 connect to %s failed (REP=%d)", target, hdr[1])
	}
	if err := drainBindAddr(conn, hdr[3]); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// buildRequest constructs the SOCKS5 CONNECT request for target (host:port).
func buildRequest(target string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("proxy: bad target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("proxy: bad port in %q", target)
	}
	req := []byte{socksVersion, cmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, atypIPv4)
			req = append(req, v4...)
		} else {
			req = append(req, atypIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("proxy: hostname too long")
		}
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	req = append(req, pb...)
	return req, nil
}

// drainBindAddr reads and discards the BND.ADDR/BND.PORT fields of a SOCKS5
// reply given the ATYP.
func drainBindAddr(conn net.Conn, atyp byte) error {
	switch atyp {
	case atypIPv4:
		if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
			return fmt.Errorf("proxy: read bind addr: %w", err)
		}
	case atypIPv6:
		if _, err := io.ReadFull(conn, make([]byte, 16)); err != nil {
			return fmt.Errorf("proxy: read bind addr: %w", err)
		}
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return fmt.Errorf("proxy: read bind addr: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(l[0]))); err != nil {
			return fmt.Errorf("proxy: read bind addr: %w", err)
		}
	default:
		return fmt.Errorf("proxy: unknown bind ATYP %d", atyp)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		return fmt.Errorf("proxy: read bind port: %w", err)
	}
	return nil
}
