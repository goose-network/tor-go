// Package directory also provides a fetcher that downloads a real microconsensus
// and the matching microdescriptors from a Tor directory cache, optionally
// through a SOCKS5 upstream proxy. This is the bootstrap path a Tor client uses
// to learn the set of relays before it can build circuits.
//
// In the C reference implementation this is done over a one-hop Tor circuit
// with BEGIN_DIR (src/feature/dirclient/dirclient.c). For bootstrap, however,
// the client may fetch the consensus directly over HTTPS from a directory
// authority's dirport; we do the same here, tunneling through the configured
// upstream proxy when one is set.
package directory

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/proxy/tor-go/internal/proxy"
)

// DirectoryAuthority is a source for directory documents. The URLs point at
// an HTTPS endpoint serving the microconsensus and microdescriptors. The Tor
// directory authorities expose these under /tor/... on their dirports; the
// consensus-health mirror also serves the microconsensus.
type DirectoryAuthority struct {
	Name string
	// ConsensusURL serves the current microconsensus.
	ConsensusURL string
	// MicrodescURL returns the URL for a microdescriptor given its hex
	// SHA-256 digest (the "m" line digest, base64-decoded then hex-encoded).
	// If nil, this authority does not serve microdescriptors.
	MicrodescURL func(hexDigest string) string
}

// DefaultAuthorities is a list of directory sources to try, in order. The
// consensus-health mirror is first because it is a stable HTTPS endpoint; the
// directory authorities follow and also serve microdescriptors.
var DefaultAuthorities = []DirectoryAuthority{
	{
		Name:         "consensus-health",
		ConsensusURL: "https://consensus-health.torproject.org/consensus-microdesc/consensus-microdesc-latest",
		MicrodescURL: nil,
	},
	{
		Name:         "moria1",
		ConsensusURL: "https://128.31.0.34:9131/tor/status-vote/current/consensus-microdesc",
		MicrodescURL: func(h string) string { return "https://128.31.0.34:9131/tor/micro/d/" + h },
	},
	{
		Name:         "maatuska",
		ConsensusURL: "https://171.25.193.78:443/tor/status-vote/current/consensus-microdesc",
		MicrodescURL: func(h string) string { return "https://171.25.193.78:443/tor/micro/d/" + h },
	},
}

// FetchOptions configures Fetch.
type FetchOptions struct {
	// UpstreamProxy is a SOCKS5 proxy address (e.g. "127.0.0.1:7890") used to
	// reach the directory sources. Empty means direct.
	UpstreamProxy string
	// Authorities is the list of sources to try. If nil, DefaultAuthorities
	// is used.
	Authorities []DirectoryAuthority
	// Timeout is the overall fetch timeout. If zero, 120s.
	Timeout time.Duration
	// MaxMicrodescs limits the number of microdescriptors fetched (to bound
	// bootstrap time in tests). If zero, all referenced microdescriptors are
	// fetched.
	MaxMicrodescs int
}

// Fetch downloads a real microconsensus and its microdescriptors, parses them,
// and returns the resulting router map. It tries each authority in order until
// one succeeds. Microdescriptors are fetched from the first authority that
// serves them.
//
// This requires outbound connectivity (directly or via UpstreamProxy) to the
// directory sources; it returns an error if none are reachable.
func Fetch(ctx context.Context, opts FetchOptions) (map[string]*Router, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 120 * time.Second
	}
	if len(opts.Authorities) == 0 {
		opts.Authorities = DefaultAuthorities
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	client := &http.Client{Transport: &dialTransport{upstream: opts.UpstreamProxy}, Timeout: 0}

	// 1. Fetch the microconsensus.
	var consensus []byte
	var consSource *DirectoryAuthority
	var errs []string
	for i := range opts.Authorities {
		a := opts.Authorities[i]
		body, err := getWith(ctx, client, a.ConsensusURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s consensus: %v", a.Name, err))
			continue
		}
		if !looksLikeConsensus(body) {
			errs = append(errs, fmt.Sprintf("%s consensus: not a consensus", a.Name))
			continue
		}
		consensus = body
		consSource = &a
		break
	}
	if consensus == nil {
		return nil, fmt.Errorf("directory: fetch consensus failed: %s", strings.Join(errs, "; "))
	}

	routers, err := ParseConsensus(consensus)
	if err != nil {
		return nil, fmt.Errorf("directory: parse consensus: %w", err)
	}

	// 2. Fetch microdescriptors from the first authority that serves them
	//    (prefer the consensus source if it has MicrodescURL).
	mdSource := consSource
	if mdSource == nil || mdSource.MicrodescURL == nil {
		for i := range opts.Authorities {
			if opts.Authorities[i].MicrodescURL != nil {
				mdSource = &opts.Authorities[i]
				break
			}
		}
	}
	if mdSource == nil || mdSource.MicrodescURL == nil {
		// No microdescriptor source; return routers with consensus fields only.
		return routers, nil
	}

	type job struct {
		hex string
		r   *Router
	}
	var jobs []job
	for _, r := range routers {
		jobs = append(jobs, job{fmt.Sprintf("%x", r.MicrodescDigest[:]), r})
		if opts.MaxMicrodescs > 0 && len(jobs) >= opts.MaxMicrodescs {
			break
		}
	}

	var mdBuf strings.Builder
	fetched := 0
	for _, j := range jobs {
		body, err := getWith(ctx, client, mdSource.MicrodescURL(j.hex))
		if err != nil {
			continue
		}
		mdBuf.Write(body)
		if !strings.HasSuffix(string(body), "\n") {
			mdBuf.WriteByte('\n')
		}
		mdBuf.WriteByte('\n') // blank-line separator between microdescs
		fetched++
	}
	if fetched == 0 {
		return routers, fmt.Errorf("directory: fetched 0 microdescriptors from %s", mdSource.Name)
	}
	if err := ParseMicrodescriptors([]byte(mdBuf.String()), routers); err != nil {
		return routers, fmt.Errorf("directory: parse microdescriptors: %w", err)
	}
	return routers, nil
}

// dialTransport is an http.RoundTripper that dials each connection through the
// SOCKS5 upstream proxy (or directly if upstream is empty), wrapping HTTPS in
// TLS. The directory authorities use self-signed certs; Tor verifies relay
// identity by digest rather than by CA, so we skip CA verification here. The
// consensus is cross-signed by a majority of authorities, so a tampered
// consensus would be detected by the signature check (out of scope for this
// minimal client).
type dialTransport struct {
	upstream string
}

func (t *dialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	// req.URL.Host may omit the port (e.g. "consensus-health.torproject.org");
	// the SOCKS5 dialer needs host:port, so add the scheme default.
	host := req.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if req.URL.Scheme == "https" {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}
	conn, err := proxy.Dial(ctx, t.upstream, host)
	if err != nil {
		return nil, fmt.Errorf("directory: dial %s: %w", host, err)
	}
	if req.URL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("directory: tls %s: %w", req.URL.Host, err)
		}
		conn = tlsConn
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Drain and close the body when the caller finishes reading.
	resp.Body = &readCloseBody{Reader: resp.Body, closer: conn}
	return resp, nil
}

// readCloseBody closes the underlying connection when the body is closed.
type readCloseBody struct {
	io.Reader
	closer io.Closer
}

func (b *readCloseBody) Close() error { return b.closer.Close() }

// getWith fetches a URL and returns its body.
func getWith(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// looksLikeConsensus sanity-checks that the document is a microconsensus.
func looksLikeConsensus(b []byte) bool {
	s := string(b)
	return strings.Contains(s, "\nr ") && strings.Contains(s, "\nm ")
}
