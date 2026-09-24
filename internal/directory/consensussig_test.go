package directory

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
)

// pemEncode wraps DER bytes in a PEM block with the given type label.
func pemEncode(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

// base64Wrap base64-encodes data and wraps it at 64 columns (PEM-style).
func base64Wrap(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(enc); i += 64 {
		end := i + 64
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}

// mintAuthority generates an RSA identity key and a separate RSA signing key,
// builds a dir-key-certificate-version 3 cert binding them, self-signs it with
// the identity key, and returns the cert text plus the parsed cert. This
// mirrors what a Tor directory authority publishes.
func mintAuthority(t *testing.T) (certText string, signingKey *rsa.PrivateKey) {
	t.Helper()
	idKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idPEM := pemRSAPublicKey(&idKey.PublicKey)
	skPEM := pemRSAPublicKey(&signKey.PublicKey)

	// Build the cert body up to and including "dir-key-certification\n".
	var b strings.Builder
	b.WriteString("dir-key-certificate-version 3\n")
	b.WriteString("fingerprint ")
	idDER, _ := x509.MarshalPKIXPublicKey(&idKey.PublicKey)
	fp := sha1.Sum(idDER)
	b.WriteString(strings.ToUpper(hex.EncodeToString(fp[:])))
	b.WriteString("\n")
	b.WriteString("dir-key-expires 2030-01-01 00:00:00\n")
	b.WriteString(idPEM)
	b.WriteString(skPEM)
	b.WriteString("dir-key-certification\n")
	signedPortion := b.String()

	digest := sha1.Sum([]byte(signedPortion))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idKey, crypto.SHA1, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b.WriteString("-----BEGIN SIGNATURE-----\n")
	b.WriteString(base64Wrap(sig))
	b.WriteString("-----END SIGNATURE-----\n")
	return b.String(), signKey
}

// pemRSAPublicKey encodes an RSA public key as a PKCS#1 "RSA PUBLIC KEY" PEM
// block, the form Tor uses in authority certs.
func pemRSAPublicKey(pub *rsa.PublicKey) string {
	der := x509.MarshalPKCS1PublicKey(pub)
	// Build PEM manually to control the type label.
	return pemEncode("RSA PUBLIC KEY", der)
}

// signConsensus signs the consensus's signed portion with the given signing
// key and appends a directory-signature block for the authority. The signed
// portion runs from "network-status-version" up to and including the
// "directory-signature " keyword (with its trailing space), so we append the
// signature header line first, compute the digest over that portion, then
// append the base64 signature block.
func signConsensus(t *testing.T, consensus string, idDigest [20]byte, signKey *rsa.PrivateKey) string {
	t.Helper()
	skDER, _ := x509.MarshalPKIXPublicKey(&signKey.PublicKey)
	skDigest := sha1.Sum(skDER)
	var b strings.Builder
	b.WriteString(consensus)
	b.WriteString("directory-signature ")
	b.WriteString(strings.ToUpper(hex.EncodeToString(idDigest[:])))
	b.WriteString(" ")
	b.WriteString(strings.ToUpper(hex.EncodeToString(skDigest[:])))
	b.WriteString("\n")
	withHeader := b.String()
	digest, err := ConsensusSignedDigest([]byte(withHeader))
	if err != nil {
		t.Fatalf("ConsensusSignedDigest: %v", err)
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, signKey, crypto.SHA1, digest)
	if err != nil {
		t.Fatal(err)
	}
	b.WriteString("-----BEGIN SIGNATURE-----\n")
	b.WriteString(base64Wrap(sig))
	b.WriteString("-----END SIGNATURE-----\n")
	return b.String()
}

// minimalConsensus builds a bare consensus header + one router entry + the
// start of the footer, ending right before the directory-signature lines. The
// signed portion runs from "network-status-version" through the first
// "directory-signature " keyword (with trailing space).
func minimalConsensus() string {
	return "network-status-version 3 microdesc\n" +
		"vote-status consensus\n" +
		"valid-after 2026-09-24 00:00:00\n" +
		"fresh-until 2026-09-24 01:00:00\n" +
		"valid-until 2026-09-24 03:00:00\n" +
		"voting-delay 300 300\n" +
		"known-flags Authority Exit Fast Guard HSDir NoEdConsensus Running Stable V2Dir Valid\n" +
		"dir-source\n" +
		"r relay AAAA+BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB 2026-09-01 00:00:00 1.2.3.4 9001 0\n" +
		"m sha256=base64digesthere\n" +
		"s Fast Guard Running Valid\n" +
		"p reject 1-65535\n" +
		"directory-footer\n"
}

func TestConsensusSignedDigestBoundaries(t *testing.T) {
	cons := minimalConsensus()
	// Append a signature line so the signed portion has an end marker.
	cons += "directory-signature 0123456789ABCDEF0123456789ABCDEF01234567 FEDCBA9876543210FEDCBA9876543210FEDCBA98\n"
	digest, err := ConsensusSignedDigest([]byte(cons))
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 20 {
		t.Fatalf("digest len %d, want 20", len(digest))
	}
	// The signed portion must end at "directory-signature " (with the space).
	// Recompute it manually to cross-check.
	start := strings.Index(cons, "network-status-version")
	end := strings.Index(cons, "\ndirectory-signature") + len("\ndirectory-signature")
	space := strings.IndexByte(cons[end:], ' ') + end + 1
	want := sha1.Sum([]byte(cons[start:space]))
	if string(digest) != string(want[:]) {
		t.Fatalf("digest mismatch: got %x want %x", digest, want)
	}
}

func TestParseConsensusSignatures(t *testing.T) {
	cons := minimalConsensus()
	cons += "directory-signature 0123456789ABCDEF0123456789ABCDEF01234567 FEDCBA9876543210FEDCBA9876543210FEDCBA98\n"
	cons += "-----BEGIN SIGNATURE-----\n"
	cons += "AAAA\n"
	cons += "-----END SIGNATURE-----\n"
	sigs, err := ParseConsensusSignatures([]byte(cons))
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("got %d sigs, want 1", len(sigs))
	}
	if sigs[0].IdentityDigest != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Errorf("identity digest = %q", sigs[0].IdentityDigest)
	}
	if sigs[0].Algorithm != "sha1" {
		t.Errorf("algorithm = %q, want sha1", sigs[0].Algorithm)
	}
	if string(sigs[0].Signature) != "\x00\x00\x00" {
		t.Errorf("signature bytes = %x", sigs[0].Signature)
	}
}

func TestParseConsensusSignaturesWithAlg(t *testing.T) {
	cons := minimalConsensus()
	cons += "directory-signature sha256 0123456789ABCDEF0123456789ABCDEF01234567 FEDCBA9876543210FEDCBA9876543210FEDCBA98\n"
	cons += "-----BEGIN SIGNATURE-----\nAAAA\n-----END SIGNATURE-----\n"
	sigs, err := ParseConsensusSignatures([]byte(cons))
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("got %d sigs, want 1", len(sigs))
	}
	if sigs[0].Algorithm != "sha256" {
		t.Errorf("algorithm = %q, want sha256", sigs[0].Algorithm)
	}
}

func TestParseAuthorityCertAndSelfSig(t *testing.T) {
	certText, _ := mintAuthority(t)
	cert, err := ParseAuthorityCert([]byte(certText))
	if err != nil {
		t.Fatalf("ParseAuthorityCert: %v", err)
	}
	// The identity digest should be non-zero.
	if cert.IdentityDigest == ([20]byte{}) {
		t.Error("identity digest is zero")
	}
	if cert.SigningKey == nil || cert.IdentityKey == nil {
		t.Error("keys not populated")
	}
}

func TestParseAuthorityCertRejectsTampered(t *testing.T) {
	certText, _ := mintAuthority(t)
	// Tamper with the cert body (flip a char in the fingerprint line).
	tampered := strings.Replace(certText, "fingerprint ", "fingerprint X", 1)
	if _, err := ParseAuthorityCert([]byte(tampered)); err == nil {
		t.Fatal("expected self-signature verification to fail on tampered cert")
	}
}

func TestVerifyConsensusSignaturesGood(t *testing.T) {
	// Mint one authority and add its identity digest to the trusted set for
	// this test. We need a quorum, so we mint enough authorities to meet it.
	// To keep the test fast, temporarily lower the quorum by minting
	// ConsensusQuorum() authorities and trusting all of them.
	origTrusted := TrustedV3AuthorityDigests
	defer func() { TrustedV3AuthorityDigests = origTrusted }()

	// Build a fresh trusted set with the minted authorities' identity digests.
	TrustedV3AuthorityDigests = map[string]bool{}
	quorum := 5 // we'll mint 5 authorities and trust them all
	certs := map[string]*AuthorityCert{}
	cons := minimalConsensus()
	for i := 0; i < quorum; i++ {
		certText, signKey := mintAuthority(t)
		cert, err := ParseAuthorityCert([]byte(certText))
		if err != nil {
			t.Fatal(err)
		}
		idHex := strings.ToUpper(hex.EncodeToString(cert.IdentityDigest[:]))
		TrustedV3AuthorityDigests[idHex] = true
		certs[strings.ToLower(idHex)] = cert
		cons = signConsensus(t, cons, cert.IdentityDigest, signKey)
	}
	// With 5 trusted authorities and 5 good signatures, quorum = 5/2+1 = 3.
	good, err := VerifyConsensusSignatures([]byte(cons), certs)
	if err != nil {
		t.Fatalf("VerifyConsensusSignatures: %v", err)
	}
	if good != quorum {
		t.Fatalf("good = %d, want %d", good, quorum)
	}
	if good < ConsensusQuorum() {
		t.Fatalf("quorum not met: %d < %d", good, ConsensusQuorum())
	}
}

func TestVerifyConsensusSignaturesRejectsTampered(t *testing.T) {
	origTrusted := TrustedV3AuthorityDigests
	defer func() { TrustedV3AuthorityDigests = origTrusted }()

	TrustedV3AuthorityDigests = map[string]bool{}
	quorum := 5
	certs := map[string]*AuthorityCert{}
	cons := minimalConsensus()
	for i := 0; i < quorum; i++ {
		certText, signKey := mintAuthority(t)
		cert, err := ParseAuthorityCert([]byte(certText))
		if err != nil {
			t.Fatal(err)
		}
		idHex := strings.ToUpper(hex.EncodeToString(cert.IdentityDigest[:]))
		TrustedV3AuthorityDigests[idHex] = true
		certs[strings.ToLower(idHex)] = cert
		cons = signConsensus(t, cons, cert.IdentityDigest, signKey)
	}
	// Tamper with the consensus body (after the signatures are appended, the
	// signed portion is unchanged, so the signatures no longer match the
	// document). Flip a char in the valid-after line.
	tampered := strings.Replace(cons, "valid-after 2026-09-24 00:00:00", "valid-after 2026-09-24 00:00:01", 1)
	good, err := VerifyConsensusSignatures([]byte(tampered), certs)
	if err != nil {
		t.Fatalf("VerifyConsensusSignatures: %v", err)
	}
	if good != 0 {
		t.Fatalf("tampered consensus: good = %d, want 0", good)
	}
}

func TestVerifyConsensusSignaturesIgnoresUnrecognized(t *testing.T) {
	origTrusted := TrustedV3AuthorityDigests
	defer func() { TrustedV3AuthorityDigests = origTrusted }()

	// Trust only one authority; sign with a second unrecognized one.
	TrustedV3AuthorityDigests = map[string]bool{}
	certText, signKey := mintAuthority(t)
	cert, err := ParseAuthorityCert([]byte(certText))
	if err != nil {
		t.Fatal(err)
	}
	// Do NOT add to trusted set.
	certs := map[string]*AuthorityCert{
		strings.ToLower(hex.EncodeToString(cert.IdentityDigest[:])): cert,
	}
	cons := signConsensus(t, minimalConsensus(), cert.IdentityDigest, signKey)
	good, _ := VerifyConsensusSignatures([]byte(cons), certs)
	if good != 0 {
		t.Fatalf("unrecognized authority: good = %d, want 0", good)
	}
}

func TestConsensusQuorumValue(t *testing.T) {
	// 9 trusted authorities → quorum 9/2+1 = 5.
	if got := ConsensusQuorum(); got != 5 {
		t.Fatalf("ConsensusQuorum = %d, want 5", got)
	}
	if got := NumTrustedV3Authorities(); got != 9 {
		t.Fatalf("NumTrustedV3Authorities = %d, want 9", got)
	}
}
