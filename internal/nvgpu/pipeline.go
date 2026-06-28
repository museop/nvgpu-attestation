package nvgpu

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// VerifyFilesWithOptions runs the complete verifier pipeline for split quote
// and certificate-chain files. The mandatory local checks run first; optional
// OCSP, RIM, and policy appraisal layers are applied only after the evidence is
// already proven to be a well-formed NVIDIA quote chain.
func VerifyFilesWithOptions(quotePath, certChainPath, rootsPath, expectedNonceHex string, opts VerifyOptions) (*Result, error) {
	result, quote, chain, err := verifyFilesDetailed(quotePath, certChainPath, rootsPath, expectedNonceHex, opts.VerificationTime)
	if err != nil {
		return result, err
	}
	if err := enrichResult(result, quote, chain, opts); err != nil {
		return result, err
	}
	return result, nil
}

func VerifySerializedEvidenceFileWithOptions(jsonPath, rootsPath string, index int, expectedNonceHex string, opts VerifyOptions) (*Result, error) {
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read serialized evidence: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("read roots: %w", err)
	}
	entries, err := parseSerializedEvidenceEntries(jsonData)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(entries) {
		return nil, fmt.Errorf("serialized evidence index out of range: got %d, valid range is 0..%d", index, len(entries)-1)
	}
	res, quote, chain, err := verifySerializedEntryDetailed(entries[index], rootsData, expectedNonceHex, opts.VerificationTime)
	if err != nil {
		return res, err
	}
	if err := enrichResult(res, quote, chain, opts); err != nil {
		return res, err
	}
	return res, nil
}

func VerifySerializedEvidenceAllFileWithOptions(jsonPath, rootsPath, expectedNonceHex string, opts VerifyOptions) ([]BatchItem, error) {
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read serialized evidence: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("read roots: %w", err)
	}
	entries, err := parseSerializedEvidenceEntries(jsonData)
	if err != nil {
		return nil, err
	}
	items := make([]BatchItem, 0, len(entries))
	for i, entry := range entries {
		result, quote, chain, verifyErr := verifySerializedEntryDetailed(entry, rootsData, expectedNonceHex, opts.VerificationTime)
		if verifyErr == nil {
			verifyErr = enrichResult(result, quote, chain, opts)
		}
		item := BatchItem{Index: i, Arch: entry.Arch, OK: verifyErr == nil, Result: result}
		if verifyErr != nil {
			item.Error = verifyErr.Error()
		}
		items = append(items, item)
	}
	return items, nil
}

func verifyFilesDetailed(quotePath, certChainPath, rootsPath, expectedNonceHex string, verificationTime time.Time) (*Result, *Quote, []*x509.Certificate, error) {
	quoteData, err := os.ReadFile(quotePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read quote: %w", err)
	}
	chainData, err := os.ReadFile(certChainPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read cert chain: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read roots: %w", err)
	}
	return verifyDetailed(quoteData, chainData, rootsData, expectedNonceHex, "split-files", "", verificationTime)
}

func verifySerializedEntryDetailed(entry SerializedEvidenceEntry, rootsPEM []byte, expectedNonceHex string, verificationTime time.Time) (*Result, *Quote, []*x509.Certificate, error) {
	nonceHex := strings.TrimSpace(expectedNonceHex)
	if nonceHex == "" {
		nonceHex = entry.Nonce
	}
	certChainPEM, err := base64.StdEncoding.DecodeString(entry.Certificate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode serialized certificate chain: %w", err)
	}
	quoteRaw, err := base64.StdEncoding.DecodeString(entry.Evidence)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode serialized quote: %w", err)
	}
	return verifyDetailed(quoteRaw, certChainPEM, rootsPEM, nonceHex, "serialized-json", entry.Arch, verificationTime)
}

// verifyDetailed is the behavior-preserving core pipeline shared by the simple
// APIs and the option-aware APIs. It intentionally stops before network/RIM
// appraisal so callers can inspect partial local-verification results on error.
func verifyDetailed(quoteInput, certChainPEM, rootsPEM []byte, expectedNonceHex, inputFormat, evidenceArch string, verificationTime time.Time) (*Result, *Quote, []*x509.Certificate, error) {
	quoteRaw, err := decodeHexOrRaw(quoteInput)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode quote: %w", err)
	}
	quote, err := ParseQuote(quoteRaw)
	if err != nil {
		return nil, nil, nil, err
	}
	chain, err := parsePEMCertificates(certChainPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse cert chain: %w", err)
	}
	if len(chain) == 0 {
		return nil, nil, nil, errors.New("certificate chain is empty")
	}
	roots, rootPool, err := parseRootBundle(rootsPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse root bundle: %w", err)
	}
	expectedNonce, err := parseNonce(expectedNonceHex)
	if err != nil {
		return nil, nil, nil, err
	}
	verifiedChains, err := verifyCertChain(chain, roots, rootPool, verificationTime)
	if err != nil {
		return nil, nil, chain, err
	}

	result := newVerificationResult(quote, chain[0], expectedNonce, verifiedChains, inputFormat, evidenceArch, verificationTime)
	if err := verifyNonce(result); err != nil {
		return result, quote, chain, err
	}
	if err := verifyQuoteBinding(result, quote, chain[0]); err != nil {
		return result, quote, chain, err
	}
	return result, quote, chain, nil
}

func newVerificationResult(quote *Quote, leaf *x509.Certificate, expectedNonce []byte, verifiedChains [][]string, inputFormat, evidenceArch string, verificationTime time.Time) *Result {
	result := &Result{
		QuoteSHA256:             sha256Hex(quote.Raw),
		CertChainVerified:       true,
		ExpectedNonce:           hex.EncodeToString(expectedNonce),
		QuoteNonce:              hex.EncodeToString(quote.Request.Nonce),
		ResponseNonce:           hex.EncodeToString(quote.Response.Nonce),
		NonceMatches:            bytes.Equal(expectedNonce, quote.Request.Nonce),
		MeasurementBlockCount:   int(quote.Response.MeasurementBlockCount),
		MeasurementRecordLength: quote.Response.MeasurementRecordLength,
		LeafSubject:             leaf.Subject.String(),
		VerifiedChains:          verifiedChains,
		InputFormat:             inputFormat,
		EvidenceArch:            evidenceArch,
	}
	if !verificationTime.IsZero() {
		result.VerificationTime = verificationTime.Format(time.RFC3339)
	}
	return result
}

func verifyNonce(result *Result) error {
	if result.NonceMatches {
		return nil
	}
	return fmt.Errorf("nonce mismatch: expected %s, quote carries %s", result.ExpectedNonce, result.QuoteNonce)
}

// verifyQuoteBinding proves that the already-verified certificate chain is the
// one that signed this quote, then binds the report FWID to the leaf FWID.
func verifyQuoteBinding(result *Result, quote *Quote, leaf *x509.Certificate) error {
	sigOK, err := verifyQuoteSignature(quote.Raw, quote.Response.Signature, leaf.PublicKey)
	if err != nil {
		return err
	}
	result.QuoteSignatureVerified = sigOK
	if !result.QuoteSignatureVerified {
		return errors.New("quote signature verification failed")
	}

	populateOpaqueSummary(result, quote.Response.OpaqueFields)
	leafFWID, err := extractLeafFWID(leaf)
	if err != nil {
		return err
	}
	result.LeafCertificateFWID = leafFWID
	result.ReportFWID = hex.EncodeToString(quote.Response.OpaqueFields[opaqueFieldFWID])
	result.FWIDMatches = result.ReportFWID != "" && strings.EqualFold(result.ReportFWID, result.LeafCertificateFWID)
	if result.ReportFWID == "" {
		result.FWIDMatches = false
		return errors.New("quote does not contain FWID opaque field")
	}
	if !result.FWIDMatches {
		return fmt.Errorf("fwid mismatch: report=%s leaf=%s", result.ReportFWID, result.LeafCertificateFWID)
	}
	return nil
}

func enrichResult(result *Result, quote *Quote, chain []*x509.Certificate, opts VerifyOptions) error {
	if opts.OCSPURL == "" {
		opts.OCSPURL = defaultOCSPURL
	}
	if opts.RIMServiceURL == "" {
		opts.RIMServiceURL = defaultRIMServiceURL
	}
	if opts.VerifyOCSP {
		checks, err := checkOCSPChain(chain, 1, opts.OCSPURL)
		result.DeviceOCSPChecks = checks
		if err != nil {
			return err
		}
	}
	if opts.VerifyRIM {
		ms, driverInfo, vbiosInfo, err := verifyRIMsAndMeasurements(result, quote, opts)
		result.MeasurementVerification = ms
		result.DriverRIM = driverInfo
		result.VBIOSRIM = vbiosInfo
		if err != nil {
			return err
		}
	}
	if opts.Policy.Enabled() {
		policy := AppraisePolicy(result, opts.Policy)
		result.PolicyVerification = policy
		if !policy.Verified {
			return errors.New("policy verification failed")
		}
	}
	return nil
}
