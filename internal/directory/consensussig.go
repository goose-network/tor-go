// consensussig.go implements verification of v3 consensus signatures.
//
// A Tor v3 network-status consensus is signed by a majority of the trusted
// directory authorities. Each authority signs the digest of the consensus's
// "signed portion" — everything from "network-status-version" up to and
// including the "directory-signature " keyword — with its RSA signing key,
// over SHA-1 for the legacy signature form or SHA-256 for the
// "directory-signature sha256" form (consensus method 12+; the live network
// now signs sha256-only). The signature is a raw RSA public-key operation
// over the bare digest (crypto_pk_private_sign = RSA_private_encrypt with
// PKCS1 padding), NOT a DigestInfo scheme — rsa.VerifyPKCS1v15 cannot
// verify these. The signing key is itself certified by the authority's
// long-term RSA identity key in an authority certificate, which the client
// fetches separately. A consensus is accepted once at least half+1 of the
// recognized v3 authorities have produced valid signatures.
//
// All three properties — the signed-portion span, the raw-digest RSA
// padding, and key digests being SHA-1 over the PKCS#1 RSAPublicKey DER —
// were validated against a live consensus-method-36 document and its
// authority certs (2026-10).
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
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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
	// IdentityDigest is the SHA-1 of the identity key's PKCS#1
	// RSAPublicKey DER (the authority's "v3ident" / fingerprint).
	IdentityDigest [20]byte
	// SigningKeyDigest is the SHA-1 of the signing key's PKCS#1 DER; this
	// must match the sk_hexdigest in a consensus signature line.
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

// ConsensusSignedDigest computes the digest of the consensus's signed
// portion: from the first "network-status-version" at the start of a line up
// to and including the first "directory-signature " keyword (with its
// trailing space). The algorithm is "sha1" (the legacy 3-field
// directory-signature form) or "sha256" (the 4-field form); the signed
// portion is identical for both — only the hash differs. Mirrors
// router_get_networkstatus_v3_hashes (end_c=' '), validated against a live
// consensus-method-36 document whose authorities all sign sha256.
func ConsensusSignedDigest(consensus []byte, algorithm string) ([]byte, error) {
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
	switch strings.ToLower(algorithm) {
	case "sha1":
		h := sha1.Sum(signedPortion)
		return h[:], nil
	case "sha256":
		h := sha256.Sum256(signedPortion)
		return h[:], nil
	default:
		return nil, fmt.Errorf("consensus: unsupported digest algorithm %q", algorithm)
	}
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
//     consensus signed digest for the signature's algorithm ("sha1" or
//     "sha256"; both cover the same signed portion) — a raw RSA public-key
//     operation per crypto_pk_public_checksig, not a DigestInfo scheme.
//
// The consensus is accepted if the good count is at least ConsensusQuorum().
// Since consensus method 12+ the live network signs consensuses sha256-only,
// so without the sha256 path every live consensus would count 0 signatures.
func VerifyConsensusSignatures(consensus []byte, certs map[string]*AuthorityCert) (int, error) {
	sigs, err := ParseConsensusSignatures(consensus)
	if err != nil {
		return 0, fmt.Errorf("consensus: parse signatures: %w", err)
	}
	digests := map[string][]byte{} // algorithm -> digest, computed lazily
	good := 0
	for _, sig := range sigs {
		alg := strings.ToLower(sig.Algorithm)
		if alg != "sha1" && alg != "sha256" {
			continue // unknown digest algorithm
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
		digest, ok := digests[alg]
		if !ok {
			digest, err = ConsensusSignedDigest(consensus, alg)
			if err != nil {
				return 0, fmt.Errorf("consensus: compute signed digest: %w", err)
			}
			digests[alg] = digest
		}
		if err := rsaVerifyRawDigest(cert.SigningKey, digest, sig.Signature); err != nil {
			continue // bad signature
		}
		good++
	}
	return good, nil
}

// rsaVerifyRawDigest verifies a raw-digest RSA signature the way Tor actually
// signs: crypto_pk_private_sign is RSA_private_encrypt with PKCS1_PADDING (a
// "type 1" encryption-style block), so the recovered plaintext is the bare
// digest, not a DigestInfo-wrapped one. rsa.VerifyPKCS1v15 cannot verify such
// signatures — it only accepts DigestInfo-encapsulated hashes. This mirrors
// crypto_pk_public_checksig: sig^e mod n, strip the 0x00 0x01 0xFF… 0x00
// padding, and require the remainder to equal the digest exactly.
func rsaVerifyRawDigest(pub *rsa.PublicKey, digest, sig []byte) error {
	if pub == nil {
		return errors.New("nil key")
	}
	k := pub.Size()
	if len(sig) != k {
		return fmt.Errorf("signature length %d, want key size %d", len(sig), k)
	}
	c := new(big.Int).SetBytes(sig)
	if c.Cmp(pub.N) >= 0 {
		return errors.New("signature out of range")
	}
	m := new(big.Int).Exp(c, big.NewInt(int64(pub.E)), pub.N)
	em := make([]byte, k)
	m.FillBytes(em)
	// EM = 0x00 0x01 PS(0xFF…) 0x00 <digest>
	if em[0] != 0x00 || em[1] != 0x01 {
		return errors.New("bad PKCS#1 v1.5 header")
	}
	i := 2
	for i < len(em) && em[i] == 0xff {
		i++
	}
	if i == len(em) || em[i] != 0x00 {
		return errors.New("bad PKCS#1 v1.5 padding separator")
	}
	if subtle.ConstantTimeCompare(em[i+1:], digest) != 1 {
		return errors.New("digest mismatch")
	}
	return nil
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
	if err := rsaVerifyRawDigest(identityKey, certDigest[:], sigBlock); err != nil {
		return nil, fmt.Errorf("authcert: self-signature invalid: %w", err)
	}

	cert := &AuthorityCert{
		SigningKey:  signingKey,
		IdentityKey: identityKey,
	}
	// Tor key digests/fingerprints are SHA-1 over the PKCS#1 RSAPublicKey
	// DER, not the SPKI wrapper — validated against a live authority cert
	// (fingerprint line and consensus signature lines both match this form).
	idDER := x509.MarshalPKCS1PublicKey(identityKey)
	cert.IdentityDigest = sha1.Sum(idDER)
	skDER := x509.MarshalPKCS1PublicKey(signingKey)
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
