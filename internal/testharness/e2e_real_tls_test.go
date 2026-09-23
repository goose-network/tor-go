//go:build tor_real

package testharness_test

import (
	"crypto/tls"
	"net"
)

// tlsClient wraps conn in a TLS 1.2+ client connection with the given
// ServerName, verifying the server certificate against the system roots.
func tlsClient(conn net.Conn, serverName string) (net.Conn, error) {
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}
