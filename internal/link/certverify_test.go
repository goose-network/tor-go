package link

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

// TestVerifyCertsEd25519 exercises the full CERTS verification path: it mints
// an RSA ID cert, an ed25519 ID→signing cert, an ed25519 signing→link cert
// (bound to a TLS cert), and an RSA→ed25519 crosscert, packs them into a
// CERTS cell payload, and confirms verifyCerts accepts them and reports the
// correct ed25519 + RSA identity. It then tampers with each piece in turn and
// confirms verification fails.
func TestVerifyCertsEd25519(t *testing.T) {
	now := time.Now()

	// --- RSA ID key + self-signed ID cert ---
	rsaIDKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	idCertDER, _, err := selfSignedRSACert(rsaIDKey, "rsa-id")
	if err != nil {
		t.Fatal(err)
	}

	// --- ed25519 master identity + signing key ---
	masterPub, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// ed25519 ID→signing cert (type 4): master signs signPub, includes master key.
	edIDSign := makeEd25519Cert(4, now.Add(24*time.Hour), 0x01, asKey(signPub), masterPriv, asKey(masterPub), true)
	// ed25519 signing→link cert (type 5): sign signs SHA256(tlsCertDER), includes sign key.
	tlsPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tlsDER, _, err := selfSignedRSACert(tlsPriv, "tls-link")
	if err != nil {
		t.Fatal(err)
	}
	tlsDigest := sha256.Sum256(tlsDER)
	edSignLink := makeEd25519Cert(5, now.Add(24*time.Hour), 0x03, asKey(tlsDigest[:]), signPriv, asKey(signPub), true)

	// RSA→ed25519 crosscert: RSA ID key signs SHA256(prefix + ed_key + expiration).
	crosscert := makeCrosscert(masterPub, now.Add(24*time.Hour), rsaIDKey)

	// --- Pack CERTS cell ---
	payload := packCertsCell(map[uint8][]byte{
		2: idCertDER,
		4: edIDSign,
		5: edSignLink,
		7: crosscert,
	})

	pc, err := parseCertsCell(payload)
	if err != nil {
		t.Fatalf("parseCertsCell: %v", err)
	}
	id, err := verifyCerts(pc, tlsDER, now)
	if err != nil {
		t.Fatalf("verifyCerts: %v", err)
	}
	if !id.hasEd25519 {
		t.Fatal("expected ed25519 identity")
	}
	if id.ed25519ID != asKey(masterPub) {
		t.Fatalf("ed25519 identity = %x, want %x", id.ed25519ID, masterPub)
	}
	// RSA identity digest is SHA-1 of the RSA public key in PKCS#1 (i2d_
	// RSAPublicKey) DER — computed here independently of rsaIDDigest so a
	// regression to the PKIX/SPKI form (the pre-fix bug) fails the test.
	wantRSA := sha1.Sum(x509.MarshalPKCS1PublicKey(&rsaIDKey.PublicKey))
	if id.rsaIDDigest != wantRSA {
		t.Fatalf("rsa digest = %x, want %x", id.rsaIDDigest, wantRSA)
	}

	// --- Negative: tamper the ed25519 link cert's certified key (TLS binding) ---
	bad := cloneCertsPayload(payload)
	bad = mutateCertBody(bad, 5, func(b []byte) []byte {
		// Flip a byte in the certified_key (offset: 1+1+4+1 = 7).
		b[7] ^= 0x01
		return b
	})
	pc2, err := parseCertsCell(bad)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := verifyCerts(pc2, tlsDER, now); err == nil {
		t.Fatal("verifyCerts accepted tampered link cert")
	}

	// --- Negative: tamper the crosscert ed_key ---
	bad2 := cloneCertsPayload(payload)
	bad2 = mutateCertBody(bad2, 7, func(b []byte) []byte {
		b[0] ^= 0x01
		return b
	})
	pc3, err := parseCertsCell(bad2)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := verifyCerts(pc3, tlsDER, now); err == nil {
		t.Fatal("verifyCerts accepted tampered crosscert")
	}

	// --- Negative: wrong TLS cert (binding mismatch) ---
	pc4, _ := parseCertsCell(payload)
	otherDER, _, err := selfSignedRSACert(tlsPriv, "other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCerts(pc4, otherDER, now); err == nil {
		t.Fatal("verifyCerts accepted wrong TLS cert")
	}
}

// TestVerifyCertsRSAOnly exercises the RSA-only path (no ed25519 certs).
func TestVerifyCertsRSAOnly(t *testing.T) {
	now := time.Now()
	rsaIDKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	idCertDER, _, err := selfSignedRSACert(rsaIDKey, "rsa-id")
	if err != nil {
		t.Fatal(err)
	}
	// Link cert signed by the ID key, with the same public key as the TLS cert.
	tlsPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tlsDER, _, err := selfSignedRSACert(tlsPriv, "tls-link")
	if err != nil {
		t.Fatal(err)
	}
	linkCertDER, err := signedRSACert(tlsPriv, rsaIDKey, "rsa-link")
	if err != nil {
		t.Fatal(err)
	}
	payload := packCertsCell(map[uint8][]byte{
		2: idCertDER,
		1: linkCertDER,
	})
	pc, err := parseCertsCell(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	id, err := verifyCerts(pc, tlsDER, now)
	if err != nil {
		t.Fatalf("verifyCerts RSA-only: %v", err)
	}
	if id.hasEd25519 {
		t.Fatal("did not expect ed25519 identity in RSA-only path")
	}
	// Independent PKCS#1-form digest expectation (see TestVerifyCertsEd25519).
	wantRSA := sha1.Sum(x509.MarshalPKCS1PublicKey(&rsaIDKey.PublicKey))
	if id.rsaIDDigest != wantRSA {
		t.Fatalf("rsa digest = %x, want %x", id.rsaIDDigest, wantRSA)
	}
}

// TestParseCertsCellDegenerate confirms a degenerate CERTS cell (the test
// harness placeholder {0x00, 0x00}) parses to nil so the caller falls back to
// the legacy TLS-digest check.
func TestParseCertsCellDegenerate(t *testing.T) {
	pc, err := parseCertsCell([]byte{0x00, 0x00})
	if err != nil {
		t.Fatalf("parse degenerate: %v", err)
	}
	if pc != nil && pc.idCert != nil {
		t.Fatal("degenerate CERTS should yield no idCert")
	}
}

// --- helpers ---

func selfSignedRSACert(key *rsa.PrivateKey, cn string) ([]byte, *x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return der, cert, nil
}

func signedRSACert(subjectKey *rsa.PrivateKey, issuerKey *rsa.PrivateKey, cn string) ([]byte, error) {
	subjTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rsa-id"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificate(rand.Reader, subjTmpl, issuer, &subjectKey.PublicKey, issuerKey)
}

// makeEd25519Cert builds an encoded Tor ed25519 cert.
//   - certType: the CERT_TYPE_* value
//   - validUntil: sets exp_field (hours since epoch)
//   - keyType: the cert_key_type (signed-key type)
//   - certified: the 32-byte certified key
//   - signer: the ed25519 private key that signs
//   - signingKey: the 32-byte signing key to embed (if includeSignKey)
func makeEd25519Cert(certType uint8, validUntil time.Time, keyType uint8, certified [32]byte, signer ed25519.PrivateKey, signingKey [32]byte, includeSignKey bool) []byte {
	var buf []byte
	buf = append(buf, 1) // version: trunnel constrains it to IN [1]
	buf = append(buf, certType)
	expField := uint32(validUntil.Unix() / 3600)
	var exp [4]byte
	binary.BigEndian.PutUint32(exp[:], expField)
	buf = append(buf, exp[:]...)
	buf = append(buf, keyType)
	buf = append(buf, certified[:]...)
	// Extensions.
	if includeSignKey {
		// One extension of type CERTEXT_SIGNED_WITH_KEY. ext_length counts
		// only the union body (the 32-byte signing key), per the trunnel
		// write-back in ed25519_cert.c; the u8 ext_type and u8 ext_flags sit
		// between the length and the body.
		buf = append(buf, 0x01) // n_extensions
		var extLen [2]byte
		binary.BigEndian.PutUint16(extLen[:], 32)
		buf = append(buf, extLen[:]...)
		buf = append(buf, byte(certextSignedWithKey))
		buf = append(buf, 0) // flags
		buf = append(buf, signingKey[:]...)
	} else {
		buf = append(buf, 0) // n_extensions
	}
	// Signature over everything so far.
	sig := ed25519.Sign(signer, buf)
	buf = append(buf, sig...)
	return buf
}

func asKey(b []byte) [32]byte {
	var k [32]byte
	copy(k[:], b)
	return k
}

// makeCrosscert builds an RSA→ed25519 crosscert: ed_key + expiration + RSA
// sig, mirroring tor_make_rsa_ed25519_crosscert (torcert.c:331). The RSA
// signature is a raw PKCS#1 v1.5 type-1 block over the bare SHA-256 digest
// bytes (no DigestInfo wrap), matching crypto_pk_private_sign over NSS
// (CKM_RSA_PKCS signs exactly the buffer it is given).
func makeCrosscert(edKey ed25519.PublicKey, validUntil time.Time, rsaKey *rsa.PrivateKey) []byte {
	signed := make([]byte, 0, 36)
	signed = append(signed, edKey...)
	var exp [4]byte
	binary.BigEndian.PutUint32(exp[:], uint32(validUntil.Unix()/3600))
	signed = append(signed, exp[:]...)
	h := sha256.New()
	h.Write([]byte(rsaEdCrosscertPrefix))
	h.Write(signed)
	digest := h.Sum(nil)
	// Raw PKCS#1 v1.5 type-1 block: 00 01 FF..FF 00 <digest>.
	k := rsaKey.N.BitLen() / 8
	block := make([]byte, 0, k)
	block = append(block, 0x00, 0x01)
	for i := 0; i < k-3-len(digest); i++ {
		block = append(block, 0xff)
	}
	block = append(block, 0x00)
	block = append(block, digest...)
	s := new(big.Int).Exp(new(big.Int).SetBytes(block), new(big.Int).Set(rsaKey.D), rsaKey.N)
	sig := s.Bytes()
	if len(sig) < k {
		pad := make([]byte, k-len(sig))
		sig = append(pad, sig...)
	}
	out := make([]byte, 0, len(signed)+1+len(sig))
	out = append(out, signed...)
	out = append(out, byte(len(sig)))
	out = append(out, sig...)
	return out
}

// packCertsCell packs a map of cert_type→body into a CERTS cell payload.
func packCertsCell(certs map[uint8][]byte) []byte {
	// Deterministic order by type for stable tests.
	var types []uint8
	for t := range certs {
		types = append(types, t)
	}
	// Sort types.
	for i := 0; i < len(types); i++ {
		for j := i + 1; j < len(types); j++ {
			if types[j] < types[i] {
				types[i], types[j] = types[j], types[i]
			}
		}
	}
	var out []byte
	// Leading u8 n_certs, per the certs_cell trunnel struct
	// (src/trunnel/link_handshake.trunnel).
	out = append(out, byte(len(types)))
	for _, ty := range types {
		body := certs[ty]
		out = append(out, ty)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(body)))
		out = append(out, l[:]...)
		out = append(out, body...)
	}
	return out
}

func cloneCertsPayload(p []byte) []byte {
	return append([]byte(nil), p...)
}

// mutateCertBody finds the cert entry of the given type in a CERTS payload and
// applies fn to its body, returning a new payload.
func mutateCertBody(payload []byte, certType uint8, fn func([]byte) []byte) []byte {
	var out []byte
	// Leading u8 n_certs is unchanged by any single-body mutation, so copy it
	// through and walk the entries after it.
	out = append(out, payload[0])
	rest := payload[1:]
	for len(rest) >= 3 {
		ty := rest[0]
		clen := int(binary.BigEndian.Uint16(rest[1:3]))
		out = append(out, ty)
		out = append(out, rest[1:3]...)
		body := rest[3 : 3+clen]
		if ty == certType {
			body = fn(append([]byte(nil), body...))
			// Re-encode length.
			l := len(body)
			out[len(out)-2] = byte(l >> 8)
			out[len(out)-1] = byte(l)
		}
		out = append(out, body...)
		rest = rest[3+clen:]
	}
	return out
}
