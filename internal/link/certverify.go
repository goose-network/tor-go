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
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// CERTS cell cert types (link_handshake.h).
const (
	certTypeRSA1024IDLink  = 1 // RSA identity + link (legacy)
	certTypeRSA1024IDID    = 2 // RSA identity self-signed (legacy ID cert)
	certTypeRSA1024IDAuth  = 3 // RSA identity + auth (legacy)
	certTypeEdIDSign       = 4 // ed25519: ID signs signing key
	certTypeEdSignLink     = 5 // ed25519: signing key signs TLS link key
	certTypeEdSignAuth     = 6 // ed25519: signing key signs auth key
	certTypeRSA1024IDEdID  = 7 // RSA→ed25519 cross-cert
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
	rsaIDDigest  [20]byte   // SHA-1 of the RSA ID cert's public key
	ed25519ID    [32]byte   // ed25519 master identity (zero if none)
	hasEd25519   bool
}

// parseCertsCell parses a CERTS cell payload into typed certificates. The
// payload is a sequence of (cert_type:1, cert_len:2, body:cert_len) entries.
// Returns the parsed certs and nil error on success. A degenerate/empty cell
// (no usable certs) returns (nil, nil) so the caller can fall back to the
// legacy TLS-digest check.
func parseCertsCell(payload []byte) (*parsedCerts, error) {
	pc := &parsedCerts{}
	any := false
	for len(payload) >= 3 {
		ct := payload[0]
		clen := int(binary.BigEndian.Uint16(payload[1:3]))
		payload = payload[3:]
		if clen > len(payload) {
			return nil, errors.New("link: CERTS entry overruns payload")
		}
		body := payload[:clen]
		payload = payload[clen:]
		switch ct {
		case certTypeRSA1024IDID:
			c, err := x509.ParseCertificate(body)
			if err != nil {
				return nil, fmt.Errorf("link: parse RSA ID cert: %w", err)
			}
			pc.idCert = c
			any = true
		case certTypeRSA1024IDLink:
			c, err := x509.ParseCertificate(body)
			if err != nil {
				return nil, fmt.Errorf("link: parse RSA link cert: %w", err)
			}
			pc.linkCert = c
			any = true
		case certTypeRSA1024IDAuth:
			c, err := x509.ParseCertificate(body)
			if err != nil {
				return nil, fmt.Errorf("link: parse RSA auth cert: %w", err)
			}
			pc.authCert = c
			any = true
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
			any = true
		case certTypeRSA1024IDEdID:
			pc.edRSACrosscert = append([]byte(nil), body...)
			any = true
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
	if len(r) < 1 {
		return nil, errors.New("ed25519 cert: truncated version")
	}
	r = r[1:] // version (unused)
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
		if len(r) < 2 {
			return nil, errors.New("ed25519 cert: truncated ext_length")
		}
		extLen := int(binary.BigEndian.Uint16(r[:2]))
		r = r[2:]
		if extLen > len(r) {
			return nil, errors.New("ed25519 cert: extension overruns")
		}
		ext := r[:extLen]
		r = r[extLen:]
		if len(ext) < 2 {
			return nil, errors.New("ed25519 cert: extension too short")
		}
		extType := ext[0]
		extFlags := ext[1]
		if extType == certextSignedWithKey {
			// The extension body after type+flags is the 32-byte signing key.
			if len(ext) < 2+32 {
				return nil, errors.New("ed25519 cert: signed-with-key ext too short")
			}
			if c.signingKeyIn {
				return nil, errors.New("ed25519 cert: duplicate signing key")
			}
			copy(c.signingKey[:], ext[2:2+32])
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

// verifyX509Chain checks that child is signed by parent. If selfSigned is true,
// parent==child and we verify the self-signature. This mirrors
// tor_tls_cert_is_valid (minus the name-check, which Tor doesn't require for
// link certs).
func verifyX509Chain(child, parent *x509.Certificate, now time.Time, selfSigned bool) error {
	if now.After(child.NotAfter) || now.Before(child.NotBefore) {
		return errors.New("cert not valid at this time")
	}
	if selfSigned {
		// Verify the self-signature.
		return child.CheckSignatureFrom(child)
	}
	return child.CheckSignatureFrom(parent)
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

// rsaIDDigest returns the SHA-1 digest of the RSA ID cert's public key, which
// is the relay's RSA identity fingerprint (consensus "r" line identity).
func rsaIDDigest(cert *x509.Certificate) ([20]byte, error) {
	pk, err := rsaPublicKeyFromCert(cert)
	if err != nil {
		return [20]byte{}, err
	}
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return [20]byte{}, err
	}
	// Tor's identity digest is SHA-1 of the ASN.1-encoded public key (the
	// "key digest"), matching crypto_pk_get_digests / DIGEST_SHA1.
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
	sig := cc[37 : 37+sigLen]
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
	if err := rsa.VerifyPKCS1v15(rsaIDKey, crypto.SHA256, digest, sig); err != nil {
		return fmt.Errorf("crosscert RSA signature: %w", err)
	}
	return nil
}
