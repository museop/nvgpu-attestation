package nvgpu

import (
	"fmt"
	"sort"
	"strings"

	"github.com/museop/nvgpu-attestation/internal/attest"
)

const (
	opaqueFieldDriverVersion = 3
	opaqueFieldVBIOSVersion  = 6
	opaqueFieldNVDEC0Status  = 11
	opaqueFieldFWID          = 20
	opaqueFieldVersion       = 34
	opaqueFieldChipInfo      = 35
	opaqueFieldFeatureFlag   = 36
)

type Request = attest.Request
type Response = attest.Response
type Quote = attest.Quote
type SerializedEvidenceEntry = attest.SerializedEvidenceEntry

type Result struct {
	QuoteSHA256             string              `json:"quote_sha256"`
	CertChainVerified       bool                `json:"cert_chain_verified"`
	QuoteSignatureVerified  bool                `json:"quote_signature_verified"`
	NonceMatches            bool                `json:"nonce_matches"`
	FWIDMatches             bool                `json:"fwid_matches"`
	ExpectedNonce           string              `json:"expected_nonce"`
	QuoteNonce              string              `json:"quote_nonce"`
	ResponseNonce           string              `json:"response_nonce"`
	MeasurementBlockCount   int                 `json:"measurement_block_count"`
	MeasurementRecordLength int                 `json:"measurement_record_length"`
	DriverVersion           string              `json:"driver_version,omitempty"`
	VBIOSVersion            string              `json:"vbios_version,omitempty"`
	ChipInfo                string              `json:"chip_info,omitempty"`
	FeatureFlag             string              `json:"feature_flag,omitempty"`
	NVDEC0Status            string              `json:"nvdec0_status,omitempty"`
	OpaqueDataVersion       uint64              `json:"opaque_data_version,omitempty"`
	ReportFWID              string              `json:"report_fwid,omitempty"`
	LeafCertificateFWID     string              `json:"leaf_certificate_fwid,omitempty"`
	LeafSubject             string              `json:"leaf_subject"`
	VerifiedChains          [][]string          `json:"verified_chains,omitempty"`
	InputFormat             string              `json:"input_format,omitempty"`
	EvidenceArch            string              `json:"evidence_arch,omitempty"`
	DeviceOCSPChecks        []OCSPCheck         `json:"device_ocsp_checks,omitempty"`
	DriverRIM               *RIMVerification    `json:"driver_rim,omitempty"`
	VBIOSRIM                *RIMVerification    `json:"vbios_rim,omitempty"`
	MeasurementVerification *MeasurementSummary `json:"measurement_verification,omitempty"`
	PolicyVerification      *PolicyResult       `json:"policy_verification,omitempty"`
	VerificationTime        string              `json:"verification_time,omitempty"`
}

type BatchItem struct {
	Index  int     `json:"index"`
	Arch   string  `json:"arch,omitempty"`
	OK     bool    `json:"ok"`
	Result *Result `json:"result,omitempty"`
	Error  string  `json:"error,omitempty"`
}

func ParseQuote(raw []byte) (*Quote, error) { return attest.ParseQuote(raw) }

func populateOpaqueSummary(result *Result, fields map[uint16][]byte) {
	result.DriverVersion = attest.DecodeCString(fields[opaqueFieldDriverVersion])
	result.VBIOSVersion = formatVBIOSVersion(fields[opaqueFieldVBIOSVersion])
	result.ChipInfo = attest.DecodeCString(fields[opaqueFieldChipInfo])
	result.FeatureFlag = decodeFeatureFlag(fields[opaqueFieldFeatureFlag])
	result.NVDEC0Status = decodeNVDEC0Status(fields[opaqueFieldNVDEC0Status])
	if versionRaw, ok := fields[opaqueFieldVersion]; ok {
		result.OpaqueDataVersion = attest.ReadLE(versionRaw)
	}
}

func decodeFeatureFlag(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	switch attest.ReadLE(data) {
	case 0:
		return "SPT"
	case 1:
		return "MPT"
	case 2:
		return "PPCIE"
	default:
		return fmt.Sprintf("unknown(%d)", attest.ReadLE(data))
	}
}

func decodeNVDEC0Status(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	switch data[0] {
	case 0xAA:
		return "enabled"
	case 0x55:
		return "disabled"
	default:
		return fmt.Sprintf("unknown(0x%02x)", data[0])
	}
}

func formatVBIOSVersion(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hexLE := make([]byte, 0, len(data)*2)
	for i := len(data) - 1; i >= 0; i-- {
		hexLE = append(hexLE, []byte(fmt.Sprintf("%02x", data[i]))...)
	}
	if len(hexLE)%2 != 0 {
		return string(hexLE)
	}
	half := len(hexLE) / 2
	if half < 2 {
		return string(hexLE)
	}
	temp := string(hexLE[half:]) + string(hexLE[half-2:half])
	parts := make([]string, 0, len(temp)/2)
	for i := 0; i+2 <= len(temp); i += 2 {
		parts = append(parts, temp[i:i+2])
	}
	return strings.Join(parts, ".")
}

func SortedOpaqueKeys(fields map[uint16][]byte) []uint16 {
	keys := make([]uint16, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
