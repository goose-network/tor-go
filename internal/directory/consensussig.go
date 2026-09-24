// consensussig.go implements verification of v3 consensus signatures.
//
// A Tor v3 network-status consensus is signed by a majority of the trusted
// directory authorities. Each authority signs the SHA-1 digest of the
// consensus's "signed portion" (everything from "network-status-version" up
// to and including the "directory-signature " keyword) with its RSA signing
// key. The signing key is itself certified by the authority's long-term RSA
// identity key in an authority certificate, which the client fetches
// separately. A consensus is accepted once at least half+1 of the recognized
// v3 authorities have produced valid signatures.
//
// This mirrors networkstatus_check_consensus_signature /
// networkstatus_check_document_signature (networkstatus.c),
// router_get_networkstatus_v3_hashes (ns_parse.c), check_signature_token
// (sigcommon.c), and authority_cert_parse_from_string (authcert_parse.c).
//
// Without this check, a directory cache or a man-in-the-middle on the dirport
// TLS connection (which we do not CA-verify) could substitute a tampered
// consensus. The signature check is the authoritative authentication of the
// directory document.

package directory

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// TrustedV3AuthorityDigests lists the RSA identity digests (the "v3ident"
// values) of the Tor network's trusted v3 directory authorities, as compiled
// into the C client (src/app/config/auth_dirs.inc). A consensus signature
// counts toward the quorum only if its identity digest is in this set.
var TrustedV3AuthorityDigests = map[string]bool{
	"0232AF901C31A04EE9848595AF9BB7620D4C5B2E": true, // dannenberg
	"23D15D965BC35114467363C165C4F724B64B4F66": true, // longclaw
	"27102BC123E7AF1D4741AE047E160C91ADC76B21": true, // maatuska
	"2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C": true, // tor26
	"49015F787433103580E3B66A1707A00E60F2D15B": true, // bastet
	"70849B868D606BAECFB6128C5E3D782029AA394F": true, // faravahar
	"E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58": true, // dizum
	"ED03BB616EB2F60BEC80151114BB25CEF515B226": true, // gabelmoo
	"F533C81CEF0BC0267857C99B2F471ADF249FA232": true, // moria1
}

// NumTrustedV3Authorities returns the number of recognized v3 directory
// authorities. The consensus quorum is half this number plus one.
func NumTrustedV3Authorities() int { return len(TrustedV3AuthorityDigests) }

// ConsensusQuorum returns the minimum number of good authority signatures
// required to accept a consensus (n_v3_authorities/2 + 1).
func ConsensusQuorum() int {
	return NumTrustedV3Authorities()/2 + 1
}

// AuthorityCert is a parsed directory authority certificate
// (dir-key-certificate-version 3). It binds an authority's RSA signing key
// (used to sign consensuses) to its long-term RSA identity key.
type AuthorityCert struct {
	// IdentityDigest is the SHA-1 of the identity key's SPKI DER (the
	// authority's "v3ident").
	IdentityDigest [20]byte
	// SigningKeyDigest is the SHA-1 of the signing key's SPKI DER; this must
	// match the sk_hexdigest in a consensus signature line.
	SigningKeyDigest [20]byte
	// SigningKey is the RSA public key that signs consensuses.
	SigningKey *rsa.PublicKey
	// IdentityKey is the RSA public key that signs the cert itself.
	IdentityKey *rsa.PublicKey
}

// ConsensusSignature is one parsed directory-signature block from the
// consensus footer.
type ConsensusSignature struct {
	// IdentityDigest is the authority's identity digest (hex, uppercased as
	// in the document).
	IdentityDigest string
	// SigningKeyDigest is the signing key digest (hex).
	SigningKeyDigest string
	// Algorithm is "sha1" for the default form, or empty (treated as sha1).
	Algorithm string
	// Signature is the raw RSA signature bytes.
	Signature []byte
}

// ParseConsensusSignatures extracts the directory-signature blocks from a
// consensus document's footer. Each block is:
//
//	directory-signature <identity_hex> <signing_key_hex>
//	-----BEGIN SIGNATURE-----
//	<base64 signature lines>
//	-----END SIGNATURE-----
//
// or, for non-SHA1 algorithms:
//
//	directory-signature <alg> <identity_hex> <signing_key_hex>
//	...
func ParseConsensusSignatures(consensus []byte) ([]ConsensusSignature, error) {
	var sigs []ConsensusSignature
	sc := bufio.NewScanner(bytes.NewReader(consensus))
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	var pending *ConsensusSignature
	var b64 strings.Builder
	inSig := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "directory-signature "):
			// Flush any pending signature.
			if pending != nil {
				raw, err := base64.StdEncoding.DecodeString(b64.String())
				if err != nil {
					return nil, fmt.Errorf("consensus sig: bad base64: %w", err)
				}
				pending.Signature = raw
				sigs = append(sigs, *pending)
				pending = nil
				b64.Reset()
			}
			fields := strings.Fields(line)
			pending = &ConsensusSignature{}
			if len(fields) == 3 {
				// directory-signature <id> <sk>
				pending.IdentityDigest = strings.ToUpper(fields[1])
				pending.SigningKeyDigest = strings.ToUpper(fields[2])
				pending.Algorithm = "sha1"
			} else if len(fields) == 4 {
				// directory-signature <alg> <id> <sk>
				pending.Algorithm = strings.ToLower(fields[1])
				pending.IdentityDigest = strings.ToUpper(fields[2])
				pending.SigningKeyDigest = strings.ToUpper(fields[3])
			} else {
				return nil, fmt.Errorf("consensus sig: malformed directory-signature line: %q", line)
			}
			inSig = false
		case line == "-----BEGIN SIGNATURE-----":
			inSig = true
			b64.Reset()
		case line == "-----END SIGNATURE-----":
			if pending == nil {
				return nil, errors.New("consensus sig: END SIGNATURE without BEGIN")
			}
			raw, err := base64.StdEncoding.DecodeString(b64.String())
			if err != nil {
				return nil, fmt.Errorf("consensus sig: bad base64: %w", err)
			}
			pending.Signature = raw
			sigs = append(sigs, *pending)
			pending = nil
			b64.Reset()
			inSig = false
		case inSig:
			b64.WriteString(line)
		}
	}
	if sc.Err() != nil {
		return nil, sc.Err()
	}
	// Flush a trailing signature that lacked an explicit END (defensive).
	if pending != nil && b64.Len() > 0 {
		raw, err := base64.StdEncoding.DecodeString(b64.String())
		if err == nil {
			pending.Signature = raw
			sigs = append(sigs, *pending)
		}
	}
	return sigs, nil
}

// ConsensusSignedDigest computes the SHA-1 digest of the consensus's signed
// portion: from the first "network-status-version" at the start of a line up
// to and including the first "directory-signature " keyword (with its
// trailing space). This is the digest each authority signs. Mirrors
// router_get_networkstatus_v3_hashes (end_c=' ').
func ConsensusSignedDigest(consensus []byte) ([]byte, error) {
	startStr := "network-status-version"
	endStr := "\ndirectory-signature"
	start := bytes.Index(consensus, []byte(startStr))
	if start < 0 {
		return nil, errors.New("consensus: no network-status-version")
	}
	if start != 0 && consensus[start-1] != '\n' {
		return nil, errors.New("consensus: network-status-version not at start of line")
	}
	// Find the end marker after the start.
	end := bytes.Index(consensus[start:], []byte(endStr))
	if end < 0 {
		return nil, errors.New("consensus: no directory-signature")
	}
	end += start
	// Move past endStr to the first space (end_c=' '), then one past it.
	after := end + len(endStr)
	spaceIdx := bytes.IndexByte(consensus[after:], ' ')
	if spaceIdx < 0 {
		return nil, errors.New("consensus: no space after directory-signature")
	}
	signedPortion := consensus[start : after+spaceIdx+1]
	h := sha1.Sum(signedPortion)
	return h[:], nil
}

// VerifyConsensusSignatures verifies the signatures on a consensus document
// and returns the number of good signatures from recognized v3 authorities.
// certs maps an authority identity digest (lowercase hex) to its parsed
// authority certificate. The caller is responsible for fetching the certs
// (see FetchAuthorityCert).
//
// A signature is "good" if:
//  1. The identity digest is a recognized v3 authority.
//  2. A cert is present for that identity, and the cert's signing-key digest
//     matches the signature's signing-key digest.
//  3. RSA-verifying the signature with the cert's signing key yields the
//     consensus signed digest (PKCS#1 v1.5 over the raw SHA-1 digest — Tor
//     uses crypto_pk_public_checksig, which is raw RSA public-key operation
//     on the digest, equivalent to PKCS1v15 with an unpadded digest).
//
// The consensus is accepted if the good count is at least ConsensusQuorum().
func VerifyConsensusSignatures(consensus []byte, certs map[string]*AuthorityCert) (int, error) {
	digest, err := ConsensusSignedDigest(consensus)
	if err != nil {
		return 0, fmt.Errorf("consensus: compute signed digest: %w", err)
	}
	sigs, err := ParseConsensusSignatures(consensus)
	if err != nil {
		return 0, fmt.Errorf("consensus: parse signatures: %w", err)
	}
	good := 0
	for _, sig := range sigs {
		if sig.Algorithm != "sha1" {
			// We only verify SHA-1 signatures (the default). Other algorithms
			// (e.g. sha256) are skipped; they would need a SHA-256 signed
			// digest, which we don't compute here.
			continue
		}
		idLower := strings.ToLower(sig.IdentityDigest)
		if !TrustedV3AuthorityDigests[strings.ToUpper(sig.IdentityDigest)] {
			continue // not a recognized authority
		}
		cert := certs[idLower]
		if cert == nil {
			continue // missing cert; can't verify
		}
		// The cert's signing-key digest must match the signature's.
		skHex := hex.EncodeToString(cert.SigningKeyDigest[:])
		if strings.ToUpper(skHex) != sig.SigningKeyDigest {
			continue
		}
		if err := rsaVerifyConsensusSig(cert.SigningKey, digest, sig.Signature); err != nil {
			continue // bad signature
		}
		good++
	}
	return good, nil
}

// rsaVerifyConsensusSig verifies a consensus signature. Tor uses
// crypto_pk_public_checksig, which performs a raw RSA public-key operation
// (RSAES-PKCS1-v1_5 decryption) and compares the recovered plaintext to the
// digest. For a SHA-1-signed consensus, the signed value embedded in the
// PKCS#1 v1.5 padding is the 20-byte SHA-1 digest itself, so
// rsa.VerifyPKCS1v15 with crypto.SHA1 over the digest is equivalent.
func rsaVerifyConsensusSig(pub *rsa.PublicKey, digest, sig []byte) error {
	if pub == nil {
		return errors.New("nil signing key")
	}
	if len(digest) != 20 {
		return fmt.Errorf("unexpected digest length %d", len(digest))
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest, sig)
}

// ParseAuthorityCert parses a dir-key-certificate-version 3 authority
// certificate and verifies its self-signature (the identity key signs the
// cert body). Returns the parsed cert, or an error if the cert is malformed
// or the self-signature is invalid.
//
// The cert format (dir-spec.txt):
//
//	dir-key-certificate-version 3
//	<dir-identity-key PEM>
//	<dir-signing-key PEM>
//	[dir-key-crosscert ...]
//	dir-key-certification
//	-----BEGIN SIGNATURE-----
//	<base64 RSA signature by the identity key over the cert body>
//	-----END SIGNATURE-----
//
// The signed portion is from "dir-key-certificate-version" through
// "dir-key-certification\n" (the keyword line), SHA-1.
func ParseAuthorityCert(text []byte) (*AuthorityCert, error) {
	// Locate the signed portion boundaries.
	startStr := "dir-key-certificate-version"
	endStr := "\ndir-key-certification"
	start := bytes.Index(text, []byte(startStr))
	if start < 0 {
		return nil, errors.New("authcert: no dir-key-certificate-version")
	}
	if start != 0 && text[start-1] != '\n' {
		return nil, errors.New("authcert: version not at start of line")
	}
	end := bytes.Index(text[start:], []byte(endStr))
	if end < 0 {
		return nil, errors.New("authcert: no dir-key-certification")
	}
	end += start
	// The signed portion ends at the newline after "dir-key-certification"
	// (end_c='\n' in router_get_hash_impl).
	nl := bytes.IndexByte(text[end+len(endStr):], '\n')
	if nl < 0 {
		return nil, errors.New("authcert: no newline after dir-key-certification")
	}
	signedPortion := text[start : end+len(endStr)+nl+1]
	certDigest := sha1.Sum(signedPortion)

	// Parse the PEM key blocks and the signature.
	identityKey, signingKey, sigBlock, err := parseAuthCertParts(text)
	if err != nil {
		return nil, err
	}
	if identityKey == nil || signingKey == nil {
		return nil, errors.New("authcert: missing identity or signing key")
	}
	// Verify the self-signature: the identity key signs the cert digest.
	if sigBlock == nil {
		return nil, errors.New("authcert: missing signature")
	}
	if err := rsa.VerifyPKCS1v15(identityKey, crypto.SHA1, certDigest[:], sigBlock); err != nil {
		return nil, fmt.Errorf("authcert: self-signature invalid: %w", err)
	}

	cert := &AuthorityCert{
		SigningKey:  signingKey,
		IdentityKey: identityKey,
	}
	idDER, err := x509.MarshalPKIXPublicKey(identityKey)
	if err != nil {
		return nil, fmt.Errorf("authcert: marshal identity key: %w", err)
	}
	cert.IdentityDigest = sha1.Sum(idDER)
	skDER, err := x509.MarshalPKIXPublicKey(signingKey)
	if err != nil {
		return nil, fmt.Errorf("authcert: marshal signing key: %w", err)
	}
	cert.SigningKeyDigest = sha1.Sum(skDER)
	return cert, nil
}

// parseAuthCertParts extracts the identity key, signing key, and the
// dir-key-certification signature from a cert document. The keys are PEM
// blocks labeled "RSA PUBLIC KEY"; the signature is a base64 block between
// BEGIN/END SIGNATURE lines after "dir-key-certification".
func parseAuthCertParts(text []byte) (*rsa.PublicKey, *rsa.PublicKey, []byte, error) {
	// Find the two "RSA PUBLIC KEY" PEM blocks in order: first is identity,
	// second is signing.
	var pemBlocks [][]byte
	rest := text
	for {
		idx := bytes.Index(rest, []byte("-----BEGIN RSA PUBLIC KEY-----"))
		if idx < 0 {
			break
		}
		end := bytes.Index(rest[idx:], []byte("-----END RSA PUBLIC KEY-----"))
		if end < 0 {
			return nil, nil, nil, errors.New("authcert: unterminated RSA PUBLIC KEY block")
		}
		end += idx + len("-----END RSA PUBLIC KEY-----")
		pemBlocks = append(pemBlocks, rest[idx:end])
		rest = rest[end:]
	}
	if len(pemBlocks) < 2 {
		return nil, nil, nil, errors.New("authcert: need two RSA PUBLIC KEY blocks")
	}
	idKey, err := parseRSAPublicKeyPEM(pemBlocks[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authcert: identity key: %w", err)
	}
	signKey, err := parseRSAPublicKeyPEM(pemBlocks[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authcert: signing key: %w", err)
	}

	// Find the signature block after "dir-key-certification".
	certLine := bytes.Index(text, []byte("dir-key-certification"))
	if certLine < 0 {
		return nil, nil, nil, errors.New("authcert: no dir-key-certification")
	}
	begin := bytes.Index(text[certLine:], []byte("-----BEGIN SIGNATURE-----"))
	if begin < 0 {
		return nil, nil, nil, errors.New("authcert: no signature block")
	}
	begin += certLine + len("-----BEGIN SIGNATURE-----")
	end := bytes.Index(text[begin:], []byte("-----END SIGNATURE-----"))
	if end < 0 {
		return nil, nil, nil, errors.New("authcert: unterminated signature block")
	}
	end += begin
	b64 := text[begin:end]
	// Strip newlines.
	b64 = bytes.ReplaceAll(b64, []byte("\n"), []byte(""))
	b64 = bytes.ReplaceAll(b64, []byte("\r"), []byte(""))
	sig, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authcert: bad signature base64: %w", err)
	}
	return idKey, signKey, sig, nil
}

// parseRSAPublicKeyPEM parses a "RSA PUBLIC KEY" PEM block (PKCS#1 RSAPublicKey)
// into an rsa.PublicKey. Tor's dir keys use the PKCS#1 public-key format,
// not the SPKI-wrapped X.509 SubjectPublicKeyInfo form.
func parseRSAPublicKeyPEM(block []byte) (*rsa.PublicKey, error) {
	p, _ := pem.Decode(block)
	if p == nil {
		return nil, errors.New("not a PEM block")
	}
	if p.Type != "RSA PUBLIC KEY" {
		// Some certs use "PUBLIC KEY" (SPKI); try that as a fallback.
		if p.Type == "PUBLIC KEY" {
			pub, err := x509.ParsePKIXPublicKey(p.Bytes)
			if err != nil {
				return nil, err
			}
			rpk, ok := pub.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("not an RSA public key")
			}
			return rpk, nil
		}
		return nil, fmt.Errorf("unexpected PEM type %q", p.Type)
	}
	// PKCS#1 RSAPublicKey.
	pub, err := x509.ParsePKCS1PublicKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
