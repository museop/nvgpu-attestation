package nvgpu

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	switchOpaqueFieldVBIOSVersion     = 6
	switchOpaqueFieldFWID             = 20
	switchOpaqueFieldDevicePDI        = 22
	switchOpaqueFieldSwitchPositionID = 24
	switchOpaqueFieldSwitchLockStatus = 25
	switchOpaqueFieldSwitchGPUPDIs    = 26

	switchLS10Project    = "5612"
	switchLS10ProjectSKU = "0002"
	switchLS10ChipSKU    = "890"
)

// SwitchVerifyOptions enables optional checks on top of mandatory local
// NVSwitch attestation report verification. A zero VerificationTime means the
// X.509 verifier uses the current clock.
type SwitchVerifyOptions struct {
	VerifyOCSP        bool
	VerifyRIM         bool
	OCSPURL           string
	RIMServiceURL     string
	SwitchBIOSRIMPath string
	RIMRootPEM        string
	SWIDSchemaXSD     string
	SkipRIMOCSP       bool
	VerificationTime  time.Time
}

type SwitchResult struct {
	ReportSHA256            string              `json:"report_sha256"`
	CertChainVerified       bool                `json:"cert_chain_verified"`
	ReportSignatureVerified bool                `json:"report_signature_verified"`
	NonceMatches            bool                `json:"nonce_matches"`
	FWIDPresent             bool                `json:"fwid_present"`
	FWIDMatches             bool                `json:"fwid_matches,omitempty"`
	ExpectedNonce           string              `json:"expected_nonce"`
	ReportNonce             string              `json:"report_nonce"`
	ResponseNonce           string              `json:"response_nonce"`
	MeasurementBlockCount   int                 `json:"measurement_block_count"`
	MeasurementRecordLength int                 `json:"measurement_record_length"`
	SwitchBIOSVersion       string              `json:"switch_bios_version,omitempty"`
	SwitchBIOSRIMID         string              `json:"switch_bios_rim_id,omitempty"`
	SwitchPDI               string              `json:"switch_pdi,omitempty"`
	SwitchGPUPDIs           []string            `json:"switch_gpu_pdis,omitempty"`
	SwitchPositionID        string              `json:"switch_position_id,omitempty"`
	SwitchLockStatus        string              `json:"switch_lock_status,omitempty"`
	ReportFWID              string              `json:"report_fwid,omitempty"`
	LeafCertificateFWID     string              `json:"leaf_certificate_fwid,omitempty"`
	LeafSubject             string              `json:"leaf_subject"`
	VerifiedChains          [][]string          `json:"verified_chains,omitempty"`
	InputFormat             string              `json:"input_format,omitempty"`
	EvidenceArch            string              `json:"evidence_arch,omitempty"`
	DeviceOCSPChecks        []OCSPCheck         `json:"device_ocsp_checks,omitempty"`
	SwitchBIOSRIM           *RIMVerification    `json:"switch_bios_rim,omitempty"`
	MeasurementVerification *MeasurementSummary `json:"measurement_verification,omitempty"`
	VerificationTime        string              `json:"verification_time,omitempty"`
}

type SwitchBatchItem struct {
	Index  int           `json:"index"`
	Arch   string        `json:"arch,omitempty"`
	OK     bool          `json:"ok"`
	Result *SwitchResult `json:"result,omitempty"`
	Error  string        `json:"error,omitempty"`
}

func VerifySwitchFilesWithOptions(reportPath, certChainPath, rootsPath, expectedNonceHex string, opts SwitchVerifyOptions) (*SwitchResult, error) {
	result, quote, chain, err := verifySwitchFilesDetailed(reportPath, certChainPath, rootsPath, expectedNonceHex, opts.VerificationTime)
	if err != nil {
		return result, err
	}
	if err := enrichSwitchResult(result, quote, chain, opts); err != nil {
		return result, err
	}
	return result, nil
}

func VerifySwitchSerializedEvidenceFileWithOptions(jsonPath, rootsPath string, index int, expectedNonceHex string, opts SwitchVerifyOptions) (*SwitchResult, error) {
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
	result, quote, chain, err := verifySwitchSerializedEntryDetailed(entries[index], rootsData, expectedNonceHex, opts.VerificationTime)
	if err != nil {
		return result, err
	}
	if err := enrichSwitchResult(result, quote, chain, opts); err != nil {
		return result, err
	}
	return result, nil
}

func VerifySwitchSerializedEvidenceAllFileWithOptions(jsonPath, rootsPath, expectedNonceHex string, opts SwitchVerifyOptions) ([]SwitchBatchItem, error) {
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
	items := make([]SwitchBatchItem, 0, len(entries))
	for i, entry := range entries {
		result, quote, chain, verifyErr := verifySwitchSerializedEntryDetailed(entry, rootsData, expectedNonceHex, opts.VerificationTime)
		if verifyErr == nil {
			verifyErr = enrichSwitchResult(result, quote, chain, opts)
		}
		item := SwitchBatchItem{Index: i, Arch: entry.Arch, OK: verifyErr == nil, Result: result}
		if verifyErr != nil {
			item.Error = verifyErr.Error()
		}
		items = append(items, item)
	}
	return items, nil
}

func verifySwitchFilesDetailed(reportPath, certChainPath, rootsPath, expectedNonceHex string, verificationTime time.Time) (*SwitchResult, *Quote, []*x509.Certificate, error) {
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read switch report: %w", err)
	}
	chainData, err := os.ReadFile(certChainPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read cert chain: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read roots: %w", err)
	}
	return verifySwitchDetailed(reportData, chainData, rootsData, expectedNonceHex, "split-files", "", verificationTime)
}

func verifySwitchSerializedEntryDetailed(entry SerializedEvidenceEntry, rootsPEM []byte, expectedNonceHex string, verificationTime time.Time) (*SwitchResult, *Quote, []*x509.Certificate, error) {
	nonceHex := strings.TrimSpace(expectedNonceHex)
	if nonceHex == "" {
		nonceHex = entry.Nonce
	}
	certChainPEM, err := base64.StdEncoding.DecodeString(entry.Certificate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode serialized certificate chain: %w", err)
	}
	reportRaw, err := base64.StdEncoding.DecodeString(entry.Evidence)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode serialized switch report: %w", err)
	}
	return verifySwitchDetailed(reportRaw, certChainPEM, rootsPEM, nonceHex, "serialized-json", entry.Arch, verificationTime)
}

func verifySwitchDetailed(reportInput, certChainPEM, rootsPEM []byte, expectedNonceHex, inputFormat, evidenceArch string, verificationTime time.Time) (*SwitchResult, *Quote, []*x509.Certificate, error) {
	reportRaw, err := decodeHexOrRaw(reportInput)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode switch report: %w", err)
	}
	quote, err := ParseQuote(reportRaw)
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

	result := newSwitchResult(quote, chain[0], expectedNonce, verifiedChains, inputFormat, evidenceArch, verificationTime)
	if !result.NonceMatches {
		return result, quote, chain, fmt.Errorf("nonce mismatch: expected %s, switch report carries %s", result.ExpectedNonce, result.ReportNonce)
	}
	if err := verifySwitchReportBinding(result, quote, chain[0]); err != nil {
		return result, quote, chain, err
	}
	return result, quote, chain, nil
}

func newSwitchResult(quote *Quote, leaf *x509.Certificate, expectedNonce []byte, verifiedChains [][]string, inputFormat, evidenceArch string, verificationTime time.Time) *SwitchResult {
	result := &SwitchResult{
		ReportSHA256:            sha256Hex(quote.Raw),
		CertChainVerified:       true,
		ExpectedNonce:           hex.EncodeToString(expectedNonce),
		ReportNonce:             hex.EncodeToString(quote.Request.Nonce),
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
	populateSwitchOpaqueSummary(result, quote.Response.OpaqueFields)
	return result
}

func verifySwitchReportBinding(result *SwitchResult, quote *Quote, leaf *x509.Certificate) error {
	sigOK, err := verifyQuoteSignature(quote.Raw, quote.Response.Signature, leaf.PublicKey)
	if err != nil {
		return err
	}
	result.ReportSignatureVerified = sigOK
	if !result.ReportSignatureVerified {
		return errors.New("switch attestation report signature verification failed")
	}

	reportFWID := quote.Response.OpaqueFields[switchOpaqueFieldFWID]
	if len(reportFWID) == 0 {
		// NVIDIA's SDK treats a missing switch FWID opaque field as non-fatal.
		result.FWIDPresent = false
		return nil
	}
	result.FWIDPresent = true
	result.ReportFWID = hex.EncodeToString(reportFWID)
	leafFWID, err := extractLeafFWID(leaf)
	if err != nil {
		return err
	}
	result.LeafCertificateFWID = leafFWID
	result.FWIDMatches = strings.EqualFold(result.ReportFWID, result.LeafCertificateFWID)
	if !result.FWIDMatches {
		return fmt.Errorf("fwid mismatch: report=%s leaf=%s", result.ReportFWID, result.LeafCertificateFWID)
	}
	return nil
}

func enrichSwitchResult(result *SwitchResult, quote *Quote, chain []*x509.Certificate, opts SwitchVerifyOptions) error {
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
		ms, rimInfo, err := verifySwitchRIMAndMeasurements(result, quote, opts)
		result.MeasurementVerification = ms
		result.SwitchBIOSRIM = rimInfo
		if err != nil {
			return err
		}
	}
	return nil
}

func verifySwitchRIMAndMeasurements(result *SwitchResult, quote *Quote, opts SwitchVerifyOptions) (*MeasurementSummary, *RIMVerification, error) {
	if result.SwitchBIOSRIMID == "" {
		return nil, nil, errors.New("switch BIOS RIM ID is unavailable")
	}
	rimDoc, rimInfo, err := loadAndVerifyRIM(result.SwitchBIOSRIMID, "switch-bios", result.SwitchBIOSVersion, opts.SwitchBIOSRIMPath, VerifyOptions{
		OCSPURL:          opts.OCSPURL,
		RIMServiceURL:    opts.RIMServiceURL,
		RIMRootPEM:       opts.RIMRootPEM,
		SWIDSchemaXSD:    opts.SWIDSchemaXSD,
		SkipRIMOCSP:      opts.SkipRIMOCSP,
		VerificationTime: opts.VerificationTime,
	})
	if err != nil {
		return nil, rimInfo, err
	}
	summary, err := compareSwitchMeasurements(quote, rimDoc)
	if err != nil {
		return summary, rimInfo, err
	}
	return summary, rimInfo, nil
}

func compareSwitchMeasurements(quote *Quote, biosDoc *rimDocument) (*MeasurementSummary, error) {
	runtime := quote.Response.getMeasurements()
	golden := map[int]goldenMeasurement{}
	for idx, gm := range biosDoc.Measurements {
		if gm.Active {
			golden[idx] = gm
		}
	}
	keys := make([]int, 0, len(golden))
	for k := range golden {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	summary := &MeasurementSummary{RuntimeCount: len(runtime), ActiveGoldenCount: len(golden)}
	for _, idx := range keys {
		if idx < 0 || idx >= len(runtime) {
			summary.Mismatched = append(summary.Mismatched, MeasurementMismatch{Index: idx, Source: golden[idx].Source})
			continue
		}
		if !measurementMatches(golden[idx], runtime[idx]) {
			summary.Mismatched = append(summary.Mismatched, MeasurementMismatch{Index: idx, Source: golden[idx].Source})
		}
	}
	summary.Verified = len(summary.Mismatched) == 0
	if !summary.Verified {
		return summary, errors.New("switch runtime measurements do not match BIOS RIM golden measurements")
	}
	return summary, nil
}

func populateSwitchOpaqueSummary(result *SwitchResult, fields map[uint16][]byte) {
	result.SwitchBIOSVersion = decodeCString(fields[switchOpaqueFieldVBIOSVersion])
	arch := result.EvidenceArch
	if arch == "" {
		// The split sample files do not carry an architecture field. LS10 is the
		// only NVSwitch architecture this verifier currently supports.
		arch = "LS10"
	}
	if result.SwitchBIOSVersion != "" && strings.EqualFold(arch, "LS10") {
		result.SwitchBIOSRIMID = switchBIOSRIMID(arch, result.SwitchBIOSVersion)
	}
	result.SwitchPDI = strings.ToUpper(hex.EncodeToString(fields[switchOpaqueFieldDevicePDI]))
	result.SwitchGPUPDIs = parseSwitchGPUPDIs(fields[switchOpaqueFieldSwitchGPUPDIs])
	result.SwitchPositionID = hex.EncodeToString(fields[switchOpaqueFieldSwitchPositionID])
	result.SwitchLockStatus = hex.EncodeToString(fields[switchOpaqueFieldSwitchLockStatus])
}

func switchBIOSRIMID(arch, biosVersion string) string {
	switch strings.ToUpper(strings.TrimSpace(arch)) {
	case "LS10":
		clean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(biosVersion), ".", ""))
		return "NV_SWITCH_BIOS_" + switchLS10Project + "_" + switchLS10ProjectSKU + "_" + switchLS10ChipSKU + "_" + clean
	default:
		return ""
	}
}

func parseSwitchGPUPDIs(data []byte) []string {
	const pdiSize = 8
	const totalPDI = 8
	if len(data) < pdiSize {
		return nil
	}
	limit := len(data)
	if limit > pdiSize*totalPDI {
		limit = pdiSize * totalPDI
	}
	seen := map[string]bool{}
	var values []string
	for i := 0; i+pdiSize <= limit; i += pdiSize {
		value := strings.ToUpper(hex.EncodeToString(data[i : i+pdiSize]))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
