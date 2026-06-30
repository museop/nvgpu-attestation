package attest

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestVerifyCertChainSample(t *testing.T) {
	chainPEM, err := os.ReadFile("../../testdata/hopperCertChain.txt")
	if err != nil {
		t.Fatal(err)
	}
	rootsPEM, err := os.ReadFile("../../testdata/device-root-bundle.pem")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ParsePEMCertificates(chainPEM)
	if err != nil {
		t.Fatalf("ParsePEMCertificates(chain) error = %v", err)
	}
	roots, rootPool, err := ParseRootBundle(rootsPEM)
	if err != nil {
		t.Fatalf("ParseRootBundle() error = %v", err)
	}
	verified, err := VerifyCertChain(chain, roots, rootPool, time.Time{})
	if err != nil {
		t.Fatalf("VerifyCertChain() error = %v", err)
	}
	if len(verified) == 0 {
		t.Fatal("VerifyCertChain() returned no chains")
	}
}

func TestVerifyReportSignatureRejectsTamperedSignature(t *testing.T) {
	quoteInput, err := os.ReadFile("../../testdata/hopperAttestationReport.txt")
	if err != nil {
		t.Fatal(err)
	}
	quoteRaw, err := DecodeHexOrRaw(quoteInput)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := ParseQuote(quoteRaw)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, err := os.ReadFile("../../testdata/hopperCertChain.txt")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ParsePEMCertificates(chainPEM)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), quote.Response.Signature...)
	tampered[0] ^= 0xff
	ok, err := VerifyReportSignature(quote.Raw, tampered, chain[0].PublicKey)
	if err != nil {
		t.Fatalf("VerifyReportSignature() error = %v", err)
	}
	if ok {
		t.Fatal("VerifyReportSignature() = true for tampered signature")
	}
}

func TestVerifyReportSignatureRejectsUnsupportedKey(t *testing.T) {
	_, err := VerifyReportSignature(make([]byte, SignatureLength+1), make([]byte, SignatureLength), "not a key")
	if err == nil || !strings.Contains(err.Error(), "unsupported public key") {
		t.Fatalf("VerifyReportSignature() error = %v, want unsupported key", err)
	}
}
