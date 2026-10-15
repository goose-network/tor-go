// certverify.go implements parsing and verification of the CERTS cell from
// the v3 link handshake. The CERTS cell lets a relay prove its identity to a
// client: it carries an RSA identity certificate chain (legacy), an ed25519
// signing→link/auth certificate chain, and an RSA→ed25519 cross-certificate
// binding the two identity systems together.
//
// This mirrors src/feature/nodelist/torcert.c (or_handshake_certs_check_both,
// or_handshake_certs_ed25519_ok, or_handshake_certs_rsa_ok,
// rsa_ed25519_crosscert_check) and the trunnel CERTS/ed25519_cert encodings
// (src/trunnel/link_handshake.[ch], src/trunnel/ed25519_cert.[ch]).
//
// On a real relay the CERTS cell is mandatory and a failed check closes the
// connection (channeltls.c:2232). tor-go verifies strictly when the cell
// contains a well-formed cert chain, and falls back to the legacy TLS-cert
// SHA-1 digest check when the cell is absent or degenerate (e.g. the in-process
// test harness, which sends a placeholder CERTS cell).

package link

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// CERTS cell cert types (link_handshake.h).
const (
	certTypeRSA1024IDLink = 1 // RSA identity + link (legacy)
	certTypeRSA1024IDID   = 2 // RSA identity self-signed (legacy ID cert)
	certTypeRSA1024IDAuth = 3 // RSA identity + auth (legacy)
	certTypeEdIDSign      = 4 // ed25519: ID signs signing key
	certTypeEdSignLink    = 5 // ed25519: signing key signs TLS link key
	certTypeEdSignAuth    = 6 // ed25519: signing key signs auth key
	certTypeRSA1024IDEdID = 7 // RSA→ed25519 cross-cert
)

// ed25519 cert signed-key types (torcert.h).
const (
	signedKeyEd25519       = 0x01
	signedKeySHA256OfRSA   = 0x02
	signedKeySHA256OfX509  = 0x03
	certFlagIncludeSignKey = 0x01
	certextSignedWithKey   = 0x04
)

// rsaEdCrosscertPrefix is the domain-separation string hashed into the
// RSA→ed25519 crosscert digest (torcert.c:324).
const rsaEdCrosscertPrefix = "Tor TLS RSA/Ed25519 cross-certificate"

// ed25519SigLen is the length of an ed25519 signature.
const ed25519SigLen = 64

// ed25519CertVersion is the only certificate version trunnel accepts
// (u8 version IN [1]; ed25519_cert.c rejects anything else).
const ed25519CertVersion = 1

// parsedCerts holds the typed certificates extracted from a CERTS cell.
type parsedCerts struct {
	// RSA X.509 certificates (legacy chain).
	idCert   *x509.Certificate // certType 2 (RSA ID, self-signed)
	linkCert *x509.Certificate // certType 1 (RSA link)
	authCert *x509.Certificate // certType 3 (RSA auth)

	// ed25519 certificates (encoded form, for signature verification).
	edIDSign   *ed25519Cert // certType 4
	edSignLink *ed25519Cert // certType 5
	edSignAuth *ed25519Cert // certType 6

	// edRSA crosscert raw body (certType 7).
	edRSACrosscert []byte
}

// ed25519Cert is a parsed Tor ed25519 certificate (torcert.h tor_cert_t /
// ed25519_cert trunnel struct).
type ed25519Cert struct {
	certType     uint8
	expField     uint32 // hours since epoch
	certKeyType  uint8
	certifiedKey [32]byte
	signingKey   [32]byte // set if signing_key_included
	signingKeyIn bool
	validUntil   time.Time
	encoded      []byte // full encoded cert (for signature verification)
}

// peerIdentity is the verified identity learned from a CERTS cell.
type peerIdentity struct {
	rsaIDDigest [20]byte // SHA-1 of the RSA ID cert's public key
	ed25519ID   [32]byte // ed25519 master identity (zero if none)
	hasEd25519  bool
}

// parseCertsCell parses a CERTS cell payload into typed certificates. Per the
// certs_cell trunnel struct (src/trunnel/link_handshake.trunnel), the payload
// is a leading u8 n_certs count followed by n_certs entries of
// (cert_type:1, cert_len:2, body:cert_len). Trunnel's parser fails the whole
// cell if the entries end before n_certs (relayed failure), so we do too;
// channeltls.c additionally rejects a truncated or duplicate certificate of
// each type ("Duplicate x509/Ed25519 certificate"), so the same type twice
// is an error here as well. Returns the parsed certs and nil error on
// success. A degenerate/empty cell (no usable certs) returns (nil, nil) so
// the caller can fall back to the legacy TLS-digest check.
func parseCertsCell(payload []byte) (*parsedCerts, error) {
	pc := &parsedCerts{}
	if len(payload) < 1 {
		return nil, nil
	}
	n := int(payload[0])
	payload = payload[1:]
	any := false
	entries := 0
	seenTypes := map[uint8]bool{}
	dup := func(ct uint8) bool { return seenTypes[ct] }
	note := func(ct uint8) {
		seenTypes[ct] = true
		any = true
	}
	for entries < n {
		if len(payload) < 3 {
			// Entries ended before n_certs: truncated cell.
			return nil, errors.New("link: CERTS cell truncated")
		}
		ct := payload[0]
		clen := int(binary.BigEndian.Uint16(payload[1:3]))
		payload = payload[3:]
		if clen > len(payload) {
			return nil, errors.New("link: CERTS entry overruns payload")
		}
		body := payload[:clen]
		payload = payload[clen:]
		entries++
		if dup(ct) {
			return nil, fmt.Errorf("link: duplicate certificate type %d", ct)
		}
		switch ct {
		case certTypeRSA1024IDID:
			c, err := x509.ParseCertificate(body)
			if err != nil {
				return nil, fmt.Errorf("link: parse RSA ID cert: %w", err)
			}
			pc.idCert = c
			note(ct)
		case certTypeRSA1024IDLink:
			c, err := x509.ParseCertificate(body)
			if err != nil {
				return nil, fmt.Errorf("link: parse RSA link cert: %w", err)
			}
			pc.linkCert = c
			note(ct)
		case certTypeRSA1024IDAuth:
			c, err := x509.ParseCertificate(body)
			if err != nil {
				return nil, fmt.Errorf("link: parse RSA auth cert: %w", err)
			}
			pc.authCert = c
			note(ct)
		case certTypeEdIDSign, certTypeEdSignLink, certTypeEdSignAuth:
			ec, err := parseEd25519Cert(body)
			if err != nil {
				return nil, fmt.Errorf("link: parse ed25519 cert (type %d): %w", ct, err)
			}
			switch ct {
			case certTypeEdIDSign:
				pc.edIDSign = ec
			case certTypeEdSignLink:
				pc.edSignLink = ec
			case certTypeEdSignAuth:
				pc.edSignAuth = ec
			}
			note(ct)
		case certTypeRSA1024IDEdID:
			pc.edRSACrosscert = append([]byte(nil), body...)
			note(ct)
		}
	}
	if !any {
		return nil, nil
	}
	return pc, nil
}

// parseEd25519Cert parses a Tor ed25519 certificate from its encoded form.
// Layout (ed25519_cert trunnel):
//
//	version:1, cert_type:1, exp_field:4(BE), cert_key_type:1,
//	certified_key:32, n_extensions:1, extensions..., signature:64
//
// Each extension: ext_length:2, ext_type:1, ext_flags:1, [un_signing_key:32].
// The signature covers encoded[0 : len-64].
func parseEd25519Cert(encoded []byte) (*ed25519Cert, error) {
	if len(encoded) < ed25519SigLen {
		return nil, errors.New("ed25519 cert too short")
	}
	c := &ed25519Cert{encoded: append([]byte(nil), encoded...)}
	r := encoded
	if r[0] != ed25519CertVersion {
		// trunnel constrains the field to IN [1]; ed25519_cert.c fails the
		// whole cell on any other version.
		return nil, fmt.Errorf("ed25519 cert: unsupported version %d", r[0])
	}
	r = r[1:] // version (checked above)
	if len(r) < 1 {
		return nil, errors.New("ed25519 cert: truncated cert_type")
	}
	c.certType = r[0]
	r = r[1:]
	if len(r) < 4 {
		return nil, errors.New("ed25519 cert: truncated exp_field")
	}
	c.expField = binary.BigEndian.Uint32(r[:4])
	c.validUntil = time.Unix(int64(c.expField)*3600, 0)
	r = r[4:]
	if len(r) < 1 {
		return nil, errors.New("ed25519 cert: truncated cert_key_type")
	}
	c.certKeyType = r[0]
	r = r[1:]
	if len(r) < 32 {
		return nil, errors.New("ed25519 cert: truncated certified_key")
	}
	copy(c.certifiedKey[:], r[:32])
	r = r[32:]
	if len(r) < 1 {
		return nil, errors.New("ed25519 cert: truncated n_extensions")
	}
	nExt := int(r[0])
	r = r[1:]
	for i := 0; i < nExt; i++ {
		if len(r) < 4 {
			return nil, errors.New("ed25519 cert: truncated ext header")
		}
		// ext_length counts only the union body (the bytes AFTER the u16
		// ext_length, u8 ext_type and u8 ext_flags), matching trunnel's
		// write-back in ed25519_cert.c (written - written_before_union).
		extLen := int(binary.BigEndian.Uint16(r[:2]))
		extType := r[2]
		extFlags := r[3]
		r = r[4:]
		if extLen > len(r) {
			return nil, errors.New("ed25519 cert: extension overruns")
		}
		body := r[:extLen]
		r = r[extLen:]
		if extType == certextSignedWithKey {
			// The signed-with-key extension body is the 32-byte signing key,
			// exactly 32 bytes — trunnel requires the union body to be
			// consumed entirely (ed25519_cert.c fails on remaining != 0).
			if len(body) != 32 {
				return nil, errors.New("ed25519 cert: signed-with-key ext must be 32 bytes")
			}
			if c.signingKeyIn {
				return nil, errors.New("ed25519 cert: duplicate signing key")
			}
			copy(c.signingKey[:], body[:32])
			c.signingKeyIn = true
		} else if extFlags&certFlagIncludeSignKey != 0 {
			// Unrecognized extension flagged as affecting validation.
			return nil, fmt.Errorf("ed25519 cert: unrecognized ext type %d affects validation", extType)
		}
	}
	// The remainder must be exactly the 64-byte signature.
	if len(r) != ed25519SigLen {
		return nil, fmt.Errorf("ed25519 cert: bad trailing length %d (want %d)", len(r), ed25519SigLen)
	}
	return c, nil
}

// verifyEd25519Cert verifies the signature on an ed25519 cert using the given
// signing public key. If signer is nil, the cert's embedded signing key is
// used (requires signingKeyIn). The signature covers encoded[0:len-64].
func (c *ed25519Cert) verify(signer ed25519.PublicKey) error {
	if signer == nil {
		if !c.signingKeyIn {
			return errors.New("ed25519 cert: no signing key available")
		}
		signer = c.signingKey[:]
	}
	signedLen := len(c.encoded) - ed25519SigLen
	if signedLen <= 0 {
		return errors.New("ed25519 cert: nothing signed")
	}
	sig := c.encoded[signedLen:]
	msg := c.encoded[:signedLen]
	if !ed25519.Verify(signer, msg, sig) {
		return errors.New("ed25519 cert: signature verification failed")
	}
	return nil
}

// verifyCerts verifies a parsed CERTS cell as a client (started_here=true).
// On success it returns the learned peer identity. It mirrors
// or_handshake_certs_check_both + or_handshake_certs_ed25519_ok +
// or_handshake_certs_rsa_ok.
//
// Verification (ed25519 path, when edIDSign is present):
//  1. edIDSign must include its signing key (the master ID key self-signs).
//  2. edSignLink's certified key must equal SHA-256 of the TLS peer cert DER
//     (the link cert binds the ed25519 chain to the TLS session).
//  3. edIDSign is signed by its embedded (master) key; edSignLink is signed by
//     edIDSign's certified (signing) key.
//  4. The RSA ID cert must be self-signed and valid.
//  5. The RSA→ed25519 crosscert must bind the RSA ID key to the ed25519 master
//     identity (RSA signature over SHA-256(prefix + ed_key + expiration)).
//
// Verification (RSA-only path, when no ed25519 certs):
//  1. idCert and linkCert must be present.
//  2. linkCert must match the TLS peer cert's public key.
//  3. linkCert is signed by idCert; idCert is self-signed.
func verifyCerts(pc *parsedCerts, tlsPeerCertDER []byte, now time.Time) (*peerIdentity, error) {
	if pc == nil || pc.idCert == nil {
		// No RSA ID cert: cannot establish RSA identity. Caller falls back.
		return nil, errors.New("link: CERTS cell missing RSA ID cert")
	}

	id := &peerIdentity{}

	if pc.edIDSign != nil {
		// ed25519 path.
		if !pc.edIDSign.signingKeyIn {
			return nil, errors.New("link: ed25519 ID cert missing signing key")
		}
		// edIDSign is self-signed by its embedded master key.
		if err := pc.edIDSign.verify(pc.edIDSign.signingKey[:]); err != nil {
			return nil, fmt.Errorf("link: ed25519 ID cert: %w", err)
		}
		if pc.edIDSign.certType != certTypeEdIDSign {
			return nil, fmt.Errorf("link: ed25519 ID cert has wrong type %d", pc.edIDSign.certType)
		}
		// The signing key certified by edIDSign is its certifiedKey.
		signingKey := pc.edIDSign.certifiedKey

		if pc.edSignLink == nil {
			return nil, errors.New("link: ed25519 link cert missing")
		}
		// edSignLink's certified key must be SHA-256 of the TLS peer cert DER.
		if len(tlsPeerCertDER) == 0 {
			return nil, errors.New("link: no TLS peer cert to bind")
		}
		tlsDigest := sha256.Sum256(tlsPeerCertDER)
		if !bytes.Equal(tlsDigest[:], pc.edSignLink.certifiedKey[:]) {
			return nil, errors.New("link: ed25519 link cert does not match TLS cert")
		}
		// edSignLink is signed by the signing key.
		if err := pc.edSignLink.verify(signingKey[:]); err != nil {
			return nil, fmt.Errorf("link: ed25519 link cert: %w", err)
		}

		// Expiration check.
		if pc.edIDSign.validUntil.Before(now) || pc.edSignLink.validUntil.Before(now) {
			return nil, errors.New("link: ed25519 cert expired")
		}

		// RSA ID cert must be self-signed and valid.
		if err := verifyX509Chain(pc.idCert, pc.idCert, now, true); err != nil {
			return nil, fmt.Errorf("link: RSA ID cert: %w", err)
		}

		// RSA→ed25519 crosscert.
		if len(pc.edRSACrosscert) == 0 {
			return nil, errors.New("link: missing RSA→ed25519 crosscert")
		}
		rsaIDKey, err := rsaPublicKeyFromCert(pc.idCert)
		if err != nil {
			return nil, fmt.Errorf("link: RSA ID cert: %w", err)
		}
		if err := verifyRSAEd25519Crosscert(pc.edRSACrosscert, rsaIDKey, pc.edIDSign.signingKey[:], now); err != nil {
			return nil, fmt.Errorf("link: crosscert: %w", err)
		}

		id.ed25519ID = pc.edIDSign.signingKey
		id.hasEd25519 = true
	} else {
		// RSA-only path.
		if pc.linkCert == nil {
			return nil, errors.New("link: RSA link cert missing")
		}
		if !x509CertMatchesKey(pc.linkCert, tlsPeerCertDER) {
			return nil, errors.New("link: RSA link cert does not match TLS cert")
		}
		if err := verifyX509Chain(pc.linkCert, pc.idCert, now, false); err != nil {
			return nil, fmt.Errorf("link: RSA link cert: %w", err)
		}
		if err := verifyX509Chain(pc.idCert, pc.idCert, now, true); err != nil {
			return nil, fmt.Errorf("link: RSA ID cert: %w", err)
		}
	}

	// Compute the RSA identity digest: SHA-1 of the RSA ID cert's public key
	// (PKCS1 DER). This is what the consensus "r" line identity refers to.
	digest, err := rsaIDDigest(pc.idCert)
	if err != nil {
		return nil, fmt.Errorf("link: RSA ID digest: %w", err)
	}
	id.rsaIDDigest = digest
	return id, nil
}

// Tor's certificate-lifetime tolerances (x509_internal.h): allow certs that
// expired up to this long ago / start up to this far in the future, treating
// the rest as clock skew rather than a hard failure.
const (
	certPastSlop   = 2 * 24 * time.Hour
	certFutureSlop = 30 * 24 * time.Hour
)

// verifyX509Chain checks whether child is signed by parent (parent==child for
// a self-signed cert). It mirrors tor_tls_cert_is_valid (x509_nss.c:304):
// verify the signature over the tbsCertificate with the issuer's key, then
// check the lifetime window — unconditionally, for self-signed ID certs too
// (torcert.c: or_handshake_certs_rsa_ok and or_handshake_certs_ed25519_ok
// both call it with the ID cert as child and signer). Notably it does NOT
// enforce x509 KeyUsage or BasicConstraints — Go's CheckSignatureFrom
// rejects real relay RSA ID certs on exactly those grounds ("parent
// certificate cannot sign this kind of cert") even though they verify fine
// under Tor's own rules.
func verifyX509Chain(child, parent *x509.Certificate, now time.Time, selfSigned bool) error {
	if parent == nil || child == nil {
		return errors.New("missing certificate")
	}
	if now.After(child.NotAfter.Add(certPastSlop)) {
		return errors.New("cert not valid at this time")
	}
	if now.Add(certFutureSlop).Before(child.NotBefore) {
		return errors.New("cert not valid at this time")
	}

	// Signature over the tbsCertificate with the issuer's key only
	// (x509_nss.c uses NSS CERT_VerifySignedDataWithPublicKey, which checks
	// just this, not the issuer's KeyUsage/CA flags).
	if err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
		return fmt.Errorf("bad signature: %w", err)
	}
	return nil
}

// x509CertMatchesKey reports whether the cert's public key matches the public
// key in the TLS peer cert DER. Tor checks that the CERTS link cert is the
// same key as the TLS cert (tor_tls_cert_matches_key).
func x509CertMatchesKey(cert *x509.Certificate, tlsPeerCertDER []byte) bool {
	if len(tlsPeerCertDER) == 0 {
		return false
	}
	peer, err := x509.ParseCertificate(tlsPeerCertDER)
	if err != nil {
		return false
	}
	return pubKeyEqual(cert.PublicKey, peer.PublicKey)
}

// pubKeyEqual reports whether two public keys are equal.
func pubKeyEqual(a, b interface{}) bool {
	// Compare via marshaled SPKI DER, which is canonical for a given key.
	derA, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	derB, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(derA, derB)
}

// rsaPublicKeyFromCert extracts the RSA public key from an X.509 cert.
func rsaPublicKeyFromCert(cert *x509.Certificate) (*rsa.PublicKey, error) {
	pk, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("cert public key is not RSA")
	}
	return pk, nil
}

// rsaIDDigest returns the SHA-1 digest of the RSA ID cert's public key in
// PKCS#1 DER form (i2d_RSAPublicKey), which is the relay's RSA identity
// fingerprint (consensus "r" line identity).
func rsaIDDigest(cert *x509.Certificate) ([20]byte, error) {
	pk, err := rsaPublicKeyFromCert(cert)
	if err != nil {
		return [20]byte{}, err
	}
	der := x509.MarshalPKCS1PublicKey(pk)
	// Tor's identity digest is SHA-1 of the ASN.1-encoded public key (the
	// "key digest"), matching crypto_pk_get_digests / DIGEST_SHA1: the C
	// crypto_pk_asn1_encode serializes with i2d_RSAPublicKey (PKCS#1
	// RSAPublicKey), NOT the SPKI/PKIX form x509.MarshalPKIXPublicKey
	// produces — the two DER encodings wrap the same key material but hash
	// differently, and only the PKCS#1 form matches the fingerprint.
	return sha1.Sum(der), nil
}

// verifyRSAEd25519Crosscert verifies an RSA→ed25519 crosscert (certType 7).
// Layout (rsa_ed_crosscert trunnel):
//
//	ed_key:32, expiration:4(BE hours), sig_len:1, sig[sig_len]
//
// The signed digest is SHA-256(rsaEdCrosscertPrefix + ed_key + expiration),
// verified with the RSA ID cert's public key using PKCS#1 v1.5. The ed_key in
// the crosscert must equal the relay's ed25519 master identity. Mirrors
// rsa_ed25519_crosscert_check (torcert.c:391).
func verifyRSAEd25519Crosscert(cc []byte, rsaIDKey *rsa.PublicKey, masterEdKey []byte, now time.Time) error {
	if len(cc) < 32+4+1 {
		return errors.New("crosscert too short")
	}
	edKey := cc[:32]
	expiration := binary.BigEndian.Uint32(cc[32:36])
	sigLen := int(cc[36])
	if 37+sigLen > len(cc) {
		return errors.New("crosscert signature overruns")
	}
	if 37+sigLen != len(cc) {
		// C requires the encoded crosscert to be consumed exactly
		// (torcert.c: crosscert_len != parsed_len → "Unparseable or
		// overlong crosscert").
		return errors.New("crosscert has trailing bytes")
	}
	sig := cc[37:]
	if !bytes.Equal(edKey, masterEdKey) {
		return errors.New("crosscert ed_key does not match master identity")
	}
	// Expiration: reject if expired. expiration is in hours since epoch.
	expTime := time.Unix(int64(expiration)*3600, 0)
	if expTime.Before(now) {
		return errors.New("crosscert expired")
	}
	// Digest = SHA-256(prefix + signed portion), signed portion = ed_key+expiration.
	h := sha256.New()
	h.Write([]byte(rsaEdCrosscertPrefix))
	h.Write(cc[:36])
	digest := h.Sum(nil)
	// The signature is a raw PKCS#1 v1.5 type-1 block over the 32 digest
	// bytes themselves — NOT a DigestInfo-wrapped hash. Trust's
	// crypto_pk_public_checksig@NSS (PK11_VerifyRecover under CKM_RSA_PKCS)
	// recovers the signed bytes and compares them to the digest without any
	// DigestInfo wrap (torcert.c: rsa_ed25519_crosscert_check step -6), so
	// Go's rsa.VerifyPKCS1v15(hash, digest) rejects valid crosscerts.
	if !rsaVerifyRawPKCS1(rsaIDKey, digest, sig) {
		return errors.New("crosscert RSA signature: verification failed")
	}
	return nil
}

// rsaVerifyRawPKCS1 checks sig against data under a raw PKCS#1 v1.5 type-1
// padding block: sig^e mod n must be 00 01 FF…FF 00 <data>. This is what
// crypto_pk_public_checksig does via NSS's PK11_VerifyRecover (CKM_RSA_PKCS):
// it "recovers" the signed-to data and lets the caller compare. Standard
// DigestInfo-wrapped verification (rsa.VerifyPKCS1v15) is not equivalent
// because Tor signs the bare bytes.
func rsaVerifyRawPKCS1(pub *rsa.PublicKey, data, sig []byte) bool {
	k := (pub.N.BitLen() + 7) / 8
	if len(sig) != k {
		return false
	}
	s := new(big.Int).SetBytes(sig)
	if s.Cmp(pub.N) >= 0 {
		return false
	}
	e := big.NewInt(int64(pub.E))
	m := new(big.Int).Exp(s, e, pub.N)
	em := m.Bytes()
	// Left-pad to the modulus size.
	if len(em) < k {
		padded := make([]byte, k)
		copy(padded[k-len(em):], em)
		em = padded
	}
	// 00 01 FF... FF 00 <data>
	if len(em) < len(data)+11 {
		return false
	}
	if em[0] != 0x00 || em[1] != 0x01 {
		return false
	}
	i := 2
	for i < len(em) && em[i] == 0xff {
		i++
	}
	if i == len(em) || em[i] != 0x00 {
		return false
	}
	return bytes.Equal(em[i+1:], data)
}
