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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/goose-network/tor-go/internal/proxy"
)

// DirectoryAuthority is a source for directory documents. The URLs point at
// an HTTP(S) endpoint serving the microconsensus and microdescriptors. The Tor
// directory authorities serve these on their dirports (plain HTTP, port 80 or
// a dedicated dirport — see src/app/config/auth_dirs.inc in the C reference)
// under /tor/...; the consensus-health mirror also serves the microconsensus
// over HTTPS.
type DirectoryAuthority struct {
	Name string
	// ConsensusURL serves the current microconsensus.
	ConsensusURL string
	// MicrodescURL returns the URL for a microdescriptor given its
	// unpadded-base64 SHA-256 digest (exactly the "m" line token, as the C
	// client passes it: dirclient.c builds /tor/micro/d/<base64-digests>).
	// If nil, this authority does not serve microdescriptors.
	MicrodescURL func(base64Digest string) string
	// CertURL returns the URL for an authority certificate given its
	// SHA-1 fingerprint (the identity-key digest, lowercase hex). If nil,
	// this authority does not serve authority certs. The standard endpoint
	// is /tor/keys/fp/<fingerprint>.
	CertURL func(hexFingerprint string) string
}

// DefaultAuthorities is a list of directory sources to try, in order. The
// authorities' addresses and dirports mirror the C client's auth_dirs.inc:
// moria1 128.31.0.39:9231, tor26 217.196.147.77:80, dizum 45.66.35.11:80.
// All three serve the consensus, microdescriptors and authority certs over
// plain HTTP on their dirports. The consensus-health mirror (HTTPS) is kept
// last as a stable fallback.
var DefaultAuthorities = []DirectoryAuthority{
	{
		Name:         "moria1",
		ConsensusURL: "http://128.31.0.39:9231/tor/status-vote/current/consensus-microdesc",
		MicrodescURL: func(b64 string) string { return "http://128.31.0.39:9231/tor/micro/d/" + b64 },
		CertURL:      func(fp string) string { return "http://128.31.0.39:9231/tor/keys/fp/" + fp },
	},
	{
		Name:         "tor26",
		ConsensusURL: "http://217.196.147.77:80/tor/status-vote/current/consensus-microdesc",
		MicrodescURL: func(b64 string) string { return "http://217.196.147.77:80/tor/micro/d/" + b64 },
		CertURL:      func(fp string) string { return "http://217.196.147.77:80/tor/keys/fp/" + fp },
	},
	{
		Name:         "dizum",
		ConsensusURL: "http://45.66.35.11:80/tor/status-vote/current/consensus-microdesc",
		MicrodescURL: func(b64 string) string { return "http://45.66.35.11:80/tor/micro/d/" + b64 },
		CertURL:      func(fp string) string { return "http://45.66.35.11:80/tor/keys/fp/" + fp },
	},
	{
		Name:         "consensus-health",
		ConsensusURL: "https://consensus-health.torproject.org/consensus-microdesc/consensus-microdesc-latest",
		MicrodescURL: nil,
		CertURL:      nil,
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
	// VerifySignatures controls whether the fetched consensus is rejected
	// unless it carries valid signatures from a quorum of trusted v3
	// directory authorities. When true, Fetch also downloads the authority
	// certificates referenced by the consensus signatures and verifies each
	// signature. This is the authoritative authentication of the directory
	// document and should be enabled for any real-network use. When false
	// (the default, for backward compatibility with tests that mint their
	// own consensus), the consensus is accepted without a signature check.
	VerifySignatures bool
	// Retries is the number of times to retry the consensus fetch across all
	// authorities before giving up. If zero, each authority is tried once
	// (the legacy behavior). Retries use exponential backoff with jitter
	// (1s, 2s, 4s, ... capped at 30s), mirroring the C client's
	// download_status failure schedule. The overall Timeout still bounds
	// the total attempt time.
	Retries int
	// UseFallbacks, when true, bootstraps the consensus over a one-hop
	// CREATE_FAST circuit to a fallback directory cache (see
	// internal/fallback) instead of over HTTPS to a directory authority. This
	// is the C client's primary bootstrap path: it contacts a hardcoded
	// fallback relay's ORPort over TLS (verifying the relay's RSA identity
	// digest), builds a one-hop fast circuit, and fetches the consensus and
	// microdescriptors with BEGIN_DIR over that circuit. Fallbacks are tried
	// in order until one succeeds. When false (the default), the HTTPS
	// authority path is used.
	UseFallbacks bool

	// Dialer, when non-nil, establishes the raw TCP connection for every
	// directory fetch: the connection to the authority (no upstream) or to
	// the upstream SOCKS5 proxy (UpstreamProxy set), and the fallback
	// relays' ORPorts. Embedders use it to route the client's own traffic
	// through their network stack; nil is the system dialer.
	Dialer proxy.Dialer
}

// Fetch downloads a real microconsensus and its microdescriptors, parses them,
// and returns the resulting router map. It tries each authority in order until
// one succeeds. Microdescriptors are fetched from the first authority that
// serves them.
//
// This requires outbound connectivity (directly or via UpstreamProxy) to the
// directory sources; it returns an error if none are reachable.
func Fetch(ctx context.Context, opts FetchOptions) (map[string]*Router, error) {
	routers, _, err := FetchWithMeta(ctx, opts)
	return routers, err
}

// FetchWithMeta is like Fetch but also returns the parsed consensus metadata
// (validity timestamps), which a client uses to schedule the next consensus
// refresh before FreshUntil.
func FetchWithMeta(ctx context.Context, opts FetchOptions) (map[string]*Router, *ConsensusMeta, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 120 * time.Second
	}
	if len(opts.Authorities) == 0 {
		opts.Authorities = DefaultAuthorities
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// When the fallback path is selected, bootstrap the consensus and
	// microdescriptors over a one-hop CREATE_FAST circuit to a fallback
	// directory cache. This is the C client's primary bootstrap path and does
	// not use the HTTPS authority transport at all.
	if opts.UseFallbacks {
		return fetchViaFallbackCircuit(ctx, opts)
	}

	client := &http.Client{Transport: &dialTransport{upstream: opts.UpstreamProxy, dialer: opts.Dialer}, Timeout: 0}

	// 1. Fetch the microconsensus, retrying across authorities with
	//    exponential backoff. Each round tries every authority in order; if
	//    none succeed and retries remain, we back off and try again. This
	//    mirrors the C client's download_status failure schedule
	//    (dirclient.c: download_status_increment_failure).
	var consensus []byte
	var consSource *DirectoryAuthority
	var errs []string
	attempts := opts.Retries + 1
	for round := 0; round < attempts; round++ {
		consensus, consSource, errs = fetchConsensusOnce(ctx, client, opts.Authorities)
		if consensus != nil {
			break
		}
		if round+1 >= attempts {
			break
		}
		// Exponential backoff with jitter: 1s, 2s, 4s, ... capped at 30s.
		backoff := time.Duration(1<<round) * time.Second
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			break
		case <-time.After(backoff):
		}
		if ctx.Err() != nil {
			break
		}
	}
	if consensus == nil {
		return nil, nil, fmt.Errorf("directory: fetch consensus failed after %d round(s): %s", attempts, strings.Join(errs, "; "))
	}

	routers, err := ParseConsensus(consensus)
	if err != nil {
		return nil, nil, fmt.Errorf("directory: parse consensus: %w", err)
	}
	meta, _ := ParseConsensusMeta(consensus) // best-effort; nil if malformed

	// 1b. Verify the consensus signatures. This is the authoritative
	//     authentication of the directory document: the dirport TLS
	//     connection is not CA-verified, so without this check a
	//     man-in-the-middle could substitute a tampered consensus. We fetch
	//     the authority certificates referenced by the signatures, verify
	//     each signature, and require a quorum of good signatures.
	if opts.VerifySignatures {
		certs, err := fetchAuthorityCerts(ctx, client, opts.Authorities, consensus)
		if err != nil {
			return nil, nil, fmt.Errorf("directory: fetch authority certs: %w", err)
		}
		good, err := VerifyConsensusSignatures(consensus, certs)
		if err != nil {
			return nil, nil, fmt.Errorf("directory: verify consensus signatures: %w", err)
		}
		if good < ConsensusQuorum() {
			return nil, nil, fmt.Errorf("directory: consensus has %d good signatures, need %d", good, ConsensusQuorum())
		}
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
		return routers, meta, nil
	}

	type job struct {
		b64 string
		r   *Router
	}
	var jobs []job
	for _, r := range routers {
		// The "m" line digest is unpadded base64 (SHA-256); the dirport
		// endpoint takes exactly that token (dircache.c: DSR_DIGEST256 |
		// DSR_BASE64).
		jobs = append(jobs, job{base64.RawStdEncoding.EncodeToString(r.MicrodescDigest[:]), r})
		if opts.MaxMicrodescs > 0 && len(jobs) >= opts.MaxMicrodescs {
			break
		}
	}

	// The dirport serves batched microdescriptors
	// (/tor/micro/d/<d1>-<d2>-...; dircache.c splits on '-'), mirroring the C
	// client, which joins digests per request instead of issuing thousands of
	// round trips: a live consensus references ~7000 relays. Batches of 96
	// (a ~4KB URL, well within the dirport's limits) were verified to return
	// in full from the live authorities.
	const microdescBatch = 96
	var mdBuf strings.Builder
	fetched := 0
	for i := 0; i < len(jobs); i += microdescBatch {
		end := i + microdescBatch
		if end > len(jobs) {
			end = len(jobs)
		}
		tokens := make([]string, 0, end-i)
		for _, j := range jobs[i:end] {
			tokens = append(tokens, j.b64)
		}
		body, err := getWith(ctx, client, mdSource.MicrodescURL(strings.Join(tokens, "-")))
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
		return routers, meta, fmt.Errorf("directory: fetched 0 microdescriptors from %s", mdSource.Name)
	}
	if err := ParseMicrodescriptors([]byte(mdBuf.String()), routers); err != nil {
		return routers, meta, fmt.Errorf("directory: parse microdescriptors: %w", err)
	}
	return routers, meta, nil
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
	dialer   proxy.Dialer
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
	conn, err := proxy.DialWithDialer(ctx, t.dialer, t.upstream, host)
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

// fetchConsensusOnce tries each authority in order and returns the first
// consensus body that passes the sanity check, along with its source. It
// returns nil consensus (and the accumulated errors) if no authority
// succeeds in this round.
func fetchConsensusOnce(ctx context.Context, client *http.Client, authorities []DirectoryAuthority) ([]byte, *DirectoryAuthority, []string) {
	var consensus []byte
	var consSource *DirectoryAuthority
	var errs []string
	for i := range authorities {
		a := authorities[i]
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
	return consensus, consSource, errs
}

// looksLikeConsensus sanity-checks that the document is a microconsensus.
func looksLikeConsensus(b []byte) bool {
	s := string(b)
	return strings.Contains(s, "\nr ") && strings.Contains(s, "\nm ")
}

// fetchAuthorityCerts downloads the authority certificates referenced by the
// consensus's directory-signature blocks. It returns a map keyed by the
// authority identity digest (lowercase hex) to the parsed, self-verified
// certificate. Certificates are fetched from the first authority in the list
// that exposes a CertURL endpoint; missing or malformed certs are skipped
// (the caller's quorum check tolerates some missing authorities).
func fetchAuthorityCerts(ctx context.Context, client *http.Client, authorities []DirectoryAuthority, consensus []byte) (map[string]*AuthorityCert, error) {
	sigs, err := ParseConsensusSignatures(consensus)
	if err != nil {
		return nil, fmt.Errorf("parse signatures: %w", err)
	}
	// Collect the distinct identity digests that are recognized authorities,
	// so we only fetch certs we will actually use.
	want := map[string]bool{}
	for _, sig := range sigs {
		if TrustedV3AuthorityDigests[strings.ToUpper(sig.IdentityDigest)] {
			want[strings.ToLower(sig.IdentityDigest)] = true
		}
	}
	if len(want) == 0 {
		return nil, errors.New("no recognized authority signatures in consensus")
	}

	// Find a source that serves certs.
	var certSource *DirectoryAuthority
	for i := range authorities {
		if authorities[i].CertURL != nil {
			certSource = &authorities[i]
			break
		}
	}
	if certSource == nil {
		return nil, errors.New("no authority cert source configured")
	}

	certs := make(map[string]*AuthorityCert, len(want))
	for fp := range want {
		body, err := getWith(ctx, client, certSource.CertURL(fp))
		if err != nil {
			continue // skip missing cert
		}
		cert, err := ParseAuthorityCert(body)
		if err != nil {
			continue // skip malformed/unverifiable cert
		}
		// Confirm the cert's identity digest matches the fingerprint we
		// requested (defensive: the cache should return the right cert).
		got := strings.ToLower(hex.EncodeToString(cert.IdentityDigest[:]))
		if got != fp {
			continue
		}
		certs[fp] = cert
	}
	return certs, nil
}
