package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	fwidOID1 = []int{2, 23, 133, 5, 4, 1, 1}
	fwidOID2 = []int{2, 23, 133, 5, 4, 1}
)

func ParsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificates found")
	}
	return certs, nil
}

func ParseRootBundle(data []byte) ([]*x509.Certificate, *x509.CertPool, error) {
	certs, err := ParsePEMCertificates(data)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return certs, pool, nil
}

func VerifyCertChain(chain []*x509.Certificate, roots []*x509.Certificate, rootPool *x509.CertPool, verificationTime time.Time) ([][]string, error) {
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		if !isRootCertificate(cert, roots) {
			intermediates.AddCert(cert)
		}
	}
	verifiedChains, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   verificationTime,
	})
	if err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}
	result := make([][]string, 0, len(verifiedChains))
	for _, verified := range verifiedChains {
		names := make([]string, 0, len(verified))
		for _, cert := range verified {
			names = append(names, cert.Subject.String())
		}
		result = append(result, names)
	}
	return result, nil
}

func VerifyReportSignature(signedData, signature []byte, publicKey any) (bool, error) {
	pub, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("unsupported public key type %T", publicKey)
	}
	if len(signature) != SignatureLength {
		return false, fmt.Errorf("unexpected signature length: got %d", len(signature))
	}
	digest := sha512.Sum384(signedData[:len(signedData)-SignatureLength])
	r := new(big.Int).SetBytes(signature[:SignatureLength/2])
	s := new(big.Int).SetBytes(signature[SignatureLength/2:])
	return ecdsa.Verify(pub, digest[:], r, s), nil
}

func ExtractLeafFWID(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if oidMatches(ext.Id, fwidOID1) || oidMatches(ext.Id, fwidOID2) {
			if len(ext.Value) < 48 {
				return "", errors.New("fwid extension too short")
			}
			return hex.EncodeToString(ext.Value[len(ext.Value)-48:]), nil
		}
	}
	return "", errors.New("fwid extension not found in leaf certificate")
}

func ParseNonce(expectedNonceHex string) ([]byte, error) {
	nonce, err := hex.DecodeString(strings.TrimSpace(expectedNonceHex))
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %w", err)
	}
	if len(nonce) != 32 {
		return nil, fmt.Errorf("nonce must be exactly 32 bytes, got %d", len(nonce))
	}
	return nonce, nil
}

func isRootCertificate(cert *x509.Certificate, roots []*x509.Certificate) bool {
	for _, root := range roots {
		if bytes.Equal(cert.Raw, root.Raw) {
			return true
		}
	}
	return false
}

func oidMatches(oid []int, expected []int) bool {
	if len(oid) != len(expected) {
		return false
	}
	for i := range oid {
		if oid[i] != expected[i] {
			return false
		}
	}
	return true
}
