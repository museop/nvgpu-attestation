package nvgpu

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	requestLength   = 37
	signatureLength = 96 // Hopper/Blackwell P-384 ECDSA raw r||s
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

var (
	hopperFWIDOID1 = []int{2, 23, 133, 5, 4, 1, 1}
	hopperFWIDOID2 = []int{2, 23, 133, 5, 4, 1}
)

type Request struct {
	Version byte
	Code    byte
	Param1  byte
	Param2  byte
	Nonce   []byte
	SlotID  byte
}

type Response struct {
	Version                 byte
	Code                    byte
	Param1                  byte
	Param2                  byte
	MeasurementBlockCount   byte
	MeasurementRecordLength int
	MeasurementRecord       []byte
	Nonce                   []byte
	OpaqueFields            map[uint16][]byte
	OpaqueLength            int
	Signature               []byte
}

type Quote struct {
	Raw      []byte
	Request  Request
	Response Response
}

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

type SerializedEvidenceEntry struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
	Nonce       string `json:"nonce"`
}

type BatchItem struct {
	Index  int     `json:"index"`
	Arch   string  `json:"arch,omitempty"`
	OK     bool    `json:"ok"`
	Result *Result `json:"result,omitempty"`
	Error  string  `json:"error,omitempty"`
}

func VerifyFiles(quotePath, certChainPath, rootsPath string, expectedNonceHex string) (*Result, error) {
	quoteData, err := os.ReadFile(quotePath)
	if err != nil {
		return nil, fmt.Errorf("read quote: %w", err)
	}
	chainData, err := os.ReadFile(certChainPath)
	if err != nil {
		return nil, fmt.Errorf("read cert chain: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("read roots: %w", err)
	}
	result, err := Verify(quoteData, chainData, rootsData, expectedNonceHex)
	if result != nil {
		result.InputFormat = "split-files"
	}
	return result, err
}

func VerifySerializedEvidenceFile(jsonPath, rootsPath string, index int, expectedNonceHex string) (*Result, error) {
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read serialized evidence: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("read roots: %w", err)
	}
	return VerifySerializedEvidence(jsonData, rootsData, index, expectedNonceHex)
}

func VerifySerializedEvidenceAllFile(jsonPath, rootsPath string, expectedNonceHex string) ([]BatchItem, error) {
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read serialized evidence: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("read roots: %w", err)
	}
	return VerifySerializedEvidenceAll(jsonData, rootsData, expectedNonceHex)
}

func Verify(quoteInput, certChainPEM, rootsPEM []byte, expectedNonceHex string) (*Result, error) {
	result, _, _, err := verifyDetailed(quoteInput, certChainPEM, rootsPEM, expectedNonceHex, "", "", time.Time{})
	return result, err
}

func VerifySerializedEvidence(serializedJSON, rootsPEM []byte, index int, expectedNonceHex string) (*Result, error) {
	entries, err := parseSerializedEvidenceEntries(serializedJSON)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(entries) {
		return nil, fmt.Errorf("serialized evidence index out of range: got %d, valid range is 0..%d", index, len(entries)-1)
	}
	return verifySerializedEvidenceEntry(entries[index], rootsPEM, expectedNonceHex)
}

func VerifySerializedEvidenceAll(serializedJSON, rootsPEM []byte, expectedNonceHex string) ([]BatchItem, error) {
	entries, err := parseSerializedEvidenceEntries(serializedJSON)
	if err != nil {
		return nil, err
	}
	items := make([]BatchItem, 0, len(entries))
	for i, entry := range entries {
		result, verifyErr := verifySerializedEvidenceEntry(entry, rootsPEM, expectedNonceHex)
		item := BatchItem{
			Index:  i,
			Arch:   entry.Arch,
			OK:     verifyErr == nil,
			Result: result,
		}
		if verifyErr != nil {
			item.Error = verifyErr.Error()
		}
		items = append(items, item)
	}
	return items, nil
}

func ParseQuote(raw []byte) (*Quote, error) {
	if len(raw) <= requestLength+signatureLength {
		return nil, fmt.Errorf("quote too short: got %d bytes", len(raw))
	}

	q := &Quote{Raw: raw}
	requestRaw := raw[:requestLength]
	responseRaw := raw[requestLength:]

	q.Request = Request{
		Version: requestRaw[0],
		Code:    requestRaw[1],
		Param1:  requestRaw[2],
		Param2:  requestRaw[3],
		Nonce:   append([]byte(nil), requestRaw[4:36]...),
		SlotID:  requestRaw[36],
	}

	if len(responseRaw) < 8+32+2+signatureLength {
		return nil, fmt.Errorf("response section too short: got %d bytes", len(responseRaw))
	}
	byteIndex := 0
	measurementRecordLength := int(readLE(responseRaw[5:8]))
	byteIndex = 8
	if len(responseRaw) < byteIndex+measurementRecordLength+32+2+signatureLength {
		return nil, fmt.Errorf("response lengths are inconsistent with total size")
	}
	measurementRecord := append([]byte(nil), responseRaw[byteIndex:byteIndex+measurementRecordLength]...)
	byteIndex += measurementRecordLength
	responseNonce := append([]byte(nil), responseRaw[byteIndex:byteIndex+32]...)
	byteIndex += 32
	opaqueLength := int(readLE(responseRaw[byteIndex : byteIndex+2]))
	byteIndex += 2
	if len(responseRaw) < byteIndex+opaqueLength+signatureLength {
		return nil, fmt.Errorf("opaque length exceeds response size")
	}
	opaqueRaw := responseRaw[byteIndex : byteIndex+opaqueLength]
	byteIndex += opaqueLength
	signature := append([]byte(nil), responseRaw[byteIndex:]...)
	if len(signature) != signatureLength {
		return nil, fmt.Errorf("unexpected signature length: got %d, want %d", len(signature), signatureLength)
	}

	opaqueFields, err := parseOpaqueFields(opaqueRaw)
	if err != nil {
		return nil, err
	}

	q.Response = Response{
		Version:                 responseRaw[0],
		Code:                    responseRaw[1],
		Param1:                  responseRaw[2],
		Param2:                  responseRaw[3],
		MeasurementBlockCount:   responseRaw[4],
		MeasurementRecordLength: measurementRecordLength,
		MeasurementRecord:       measurementRecord,
		Nonce:                   responseNonce,
		OpaqueFields:            opaqueFields,
		OpaqueLength:            opaqueLength,
		Signature:               signature,
	}

	return q, nil
}

func parseOpaqueFields(raw []byte) (map[uint16][]byte, error) {
	fields := make(map[uint16][]byte)
	for i := 0; i < len(raw); {
		if len(raw[i:]) < 4 {
			return nil, errors.New("opaque data truncated")
		}
		fieldType := uint16(readLE(raw[i : i+2]))
		i += 2
		size := int(readLE(raw[i : i+2]))
		i += 2
		if len(raw[i:]) < size {
			return nil, fmt.Errorf("opaque field %d truncated", fieldType)
		}
		fields[fieldType] = append([]byte(nil), raw[i:i+size]...)
		i += size
	}
	return fields, nil
}

func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
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

func parseSerializedEvidenceEntries(data []byte) ([]SerializedEvidenceEntry, error) {
	var entries []SerializedEvidenceEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse serialized evidence json: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("serialized evidence json is empty")
	}
	for i, entry := range entries {
		if strings.TrimSpace(entry.Evidence) == "" {
			return nil, fmt.Errorf("serialized evidence entry %d is missing evidence", i)
		}
		if strings.TrimSpace(entry.Certificate) == "" {
			return nil, fmt.Errorf("serialized evidence entry %d is missing certificate", i)
		}
		if strings.TrimSpace(entry.Nonce) == "" {
			return nil, fmt.Errorf("serialized evidence entry %d is missing nonce", i)
		}
	}
	return entries, nil
}

func verifySerializedEvidenceEntry(entry SerializedEvidenceEntry, rootsPEM []byte, expectedNonceHex string) (*Result, error) {
	result, _, _, err := verifySerializedEntryDetailed(entry, rootsPEM, expectedNonceHex, time.Time{})
	return result, err
}

func parseRootBundle(data []byte) ([]*x509.Certificate, *x509.CertPool, error) {
	certs, err := parsePEMCertificates(data)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return certs, pool, nil
}

func verifyCertChain(chain []*x509.Certificate, roots []*x509.Certificate, rootPool *x509.CertPool, verificationTime time.Time) ([][]string, error) {
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

func verifyQuoteSignature(signedData, signature []byte, publicKey any) (bool, error) {
	pub, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("unsupported public key type %T", publicKey)
	}
	if len(signature) != signatureLength {
		return false, fmt.Errorf("unexpected signature length: got %d", len(signature))
	}
	digest := sha512.Sum384(signedData[:len(signedData)-signatureLength])
	r := new(big.Int).SetBytes(signature[:signatureLength/2])
	s := new(big.Int).SetBytes(signature[signatureLength/2:])
	return ecdsa.Verify(pub, digest[:], r, s), nil
}

func extractLeafFWID(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if oidMatches(ext.Id, hopperFWIDOID1) || oidMatches(ext.Id, hopperFWIDOID2) {
			if len(ext.Value) < 48 {
				return "", errors.New("fwid extension too short")
			}
			return hex.EncodeToString(ext.Value[len(ext.Value)-48:]), nil
		}
	}
	return "", errors.New("fwid extension not found in leaf certificate")
}

func populateOpaqueSummary(result *Result, fields map[uint16][]byte) {
	result.DriverVersion = decodeCString(fields[opaqueFieldDriverVersion])
	result.VBIOSVersion = formatVBIOSVersion(fields[opaqueFieldVBIOSVersion])
	result.ChipInfo = decodeCString(fields[opaqueFieldChipInfo])
	result.FeatureFlag = decodeFeatureFlag(fields[opaqueFieldFeatureFlag])
	result.NVDEC0Status = decodeNVDEC0Status(fields[opaqueFieldNVDEC0Status])
	if versionRaw, ok := fields[opaqueFieldVersion]; ok {
		result.OpaqueDataVersion = readLE(versionRaw)
	}
}

func parseNonce(expectedNonceHex string) ([]byte, error) {
	nonce, err := hex.DecodeString(strings.TrimSpace(expectedNonceHex))
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %w", err)
	}
	if len(nonce) != 32 {
		return nil, fmt.Errorf("nonce must be exactly 32 bytes, got %d", len(nonce))
	}
	return nonce, nil
}

func decodeHexOrRaw(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input")
	}

	withoutWhitespace := make([]byte, 0, len(data))
	hexCandidate := true
	for _, b := range data {
		if b == ' ' || b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		if !isHex([]byte{b}) {
			hexCandidate = false
			break
		}
		withoutWhitespace = append(withoutWhitespace, b)
	}
	if hexCandidate {
		if len(withoutWhitespace) == 0 {
			return nil, errors.New("empty input")
		}
		if len(withoutWhitespace)%2 != 0 {
			return nil, errors.New("hex input has odd length")
		}
		decoded := make([]byte, hex.DecodedLen(len(withoutWhitespace)))
		if _, err := hex.Decode(decoded, withoutWhitespace); err != nil {
			return nil, err
		}
		return decoded, nil
	}
	return append([]byte(nil), data...), nil
}

func isHex(data []byte) bool {
	for _, b := range data {
		switch {
		case b >= '0' && b <= '9':
		case b >= 'a' && b <= 'f':
		case b >= 'A' && b <= 'F':
		default:
			return false
		}
	}
	return true
}

func isRootCertificate(cert *x509.Certificate, roots []*x509.Certificate) bool {
	for _, root := range roots {
		if bytes.Equal(cert.Raw, root.Raw) {
			return true
		}
	}
	return false
}

func readLE(data []byte) uint64 {
	var v uint64
	for i := len(data) - 1; i >= 0; i-- {
		v = (v << 8) | uint64(data[i])
		if i == 0 {
			break
		}
	}
	return v
}

func decodeCString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	data = bytes.TrimRight(data, "\x00")
	return string(data)
}

func decodeFeatureFlag(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	switch readLE(data) {
	case 0:
		return "SPT"
	case 1:
		return "MPT"
	case 2:
		return "PPCIE"
	default:
		return fmt.Sprintf("unknown(%d)", readLE(data))
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

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func SortedOpaqueKeys(fields map[uint16][]byte) []uint16 {
	keys := make([]uint16, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
