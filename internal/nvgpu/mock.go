package nvgpu

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const MockDefaultNonce = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// MockQuoteOptions controls generation of test-only NVGPU-like evidence.
// The generated roots and quotes are deliberately self-signed/test-scoped and
// are not NVIDIA endorsements.
type MockRootOptions struct {
	Validity time.Duration
	Now      time.Time
}

type MockRootBundle struct {
	RootCertPEM []byte
	RootKeyPEM  []byte
	RootCert    *x509.Certificate
	RootKey     *ecdsa.PrivateKey
}

// MockQuoteOptions controls generation of test-only NVGPU-like evidence.
// The generated quote is deliberately test-scoped and is not an NVIDIA endorsement.
type MockQuoteOptions struct {
	NonceHex         string
	DriverVersion    string
	VBIOSVersion     string
	MeasurementCount int
	Validity         time.Duration
	Now              time.Time
	RootKey          *ecdsa.PrivateKey
	RootCert         *x509.Certificate
}

type MockQuoteBundle struct {
	NonceHex      string
	QuoteRaw      []byte
	QuoteHex      []byte
	CertChainPEM  []byte
	RootCertPEM   []byte
	LeafKeyPEM    []byte
	EvidenceJSON  []byte
	RootCert      *x509.Certificate
	LeafCert      *x509.Certificate
	QuoteSHA256   string
	DriverVersion string
	VBIOSVersion  string
}

// GenerateMockRootBundle creates a test-only ECDSA P-384 root key and self-signed root certificate.
func GenerateMockRootBundle(opts MockRootOptions) (*MockRootBundle, error) {
	if opts.Validity == 0 {
		opts.Validity = 365 * 24 * time.Hour
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate mock root key: %w", err)
	}
	rootCert, rootDER, err := createMockRoot(rootKey, now, opts.Validity)
	if err != nil {
		return nil, err
	}
	rootKeyPEM, err := marshalECPrivateKeyPEM(rootKey)
	if err != nil {
		return nil, err
	}
	return &MockRootBundle{
		RootCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		RootKeyPEM:  rootKeyPEM,
		RootCert:    rootCert,
		RootKey:     rootKey,
	}, nil
}

// GenerateMockQuoteBundle creates a mock root and then signs a mock quote with it.
// Prefer GenerateMockRootBundle + GenerateMockQuoteBundleFromRoot for CLI/workflows
// that need stable root material across multiple mock quotes.
func GenerateMockQuoteBundle(opts MockQuoteOptions) (*MockQuoteBundle, error) {
	root, err := GenerateMockRootBundle(MockRootOptions{Validity: opts.Validity, Now: opts.Now})
	if err != nil {
		return nil, err
	}
	opts.RootKey = root.RootKey
	opts.RootCert = root.RootCert
	return GenerateMockQuoteBundleFromRoot(opts)
}

// GenerateMockQuoteBundleFromRoot creates a mock leaf certificate and NVGPU-like quote signed under the provided test root.
func GenerateMockQuoteBundleFromRoot(opts MockQuoteOptions) (*MockQuoteBundle, error) {
	if opts.RootKey == nil {
		return nil, errors.New("mock root key is required")
	}
	if opts.RootCert == nil {
		return nil, errors.New("mock root certificate is required")
	}
	if opts.NonceHex == "" {
		opts.NonceHex = MockDefaultNonce
	}
	if opts.DriverVersion == "" {
		opts.DriverVersion = "999.0.mock"
	}
	if opts.VBIOSVersion == "" {
		opts.VBIOSVersion = "96.00.9f.00.01"
	}
	if opts.MeasurementCount == 0 {
		opts.MeasurementCount = 64
	}
	if opts.MeasurementCount < 0 || opts.MeasurementCount > 255 {
		return nil, fmt.Errorf("measurement count must be 0..255, got %d", opts.MeasurementCount)
	}
	if opts.Validity == 0 {
		opts.Validity = 365 * 24 * time.Hour
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nonce, err := parseNonce(opts.NonceHex)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate mock leaf key: %w", err)
	}
	fwid := make([]byte, 48)
	if _, err := rand.Read(fwid); err != nil {
		return nil, fmt.Errorf("generate mock fwid: %w", err)
	}
	leafCert, leafDER, err := createMockLeaf(leafKey, opts.RootKey, opts.RootCert, fwid, now, opts.Validity)
	if err != nil {
		return nil, err
	}
	quoteRaw, err := buildMockQuote(nonce, leafKey, fwid, opts.DriverVersion, opts.VBIOSVersion, opts.MeasurementCount)
	if err != nil {
		return nil, err
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: opts.RootCert.Raw})
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), rootPEM...)
	leafKeyPEM, err := marshalECPrivateKeyPEM(leafKey)
	if err != nil {
		return nil, err
	}
	evidenceJSON, err := marshalMockEvidenceJSON(opts.NonceHex, quoteRaw, chainPEM)
	if err != nil {
		return nil, err
	}
	return &MockQuoteBundle{
		NonceHex:      strings.ToLower(opts.NonceHex),
		QuoteRaw:      quoteRaw,
		QuoteHex:      []byte(hex.EncodeToString(quoteRaw) + "\n"),
		CertChainPEM:  chainPEM,
		RootCertPEM:   rootPEM,
		LeafKeyPEM:    leafKeyPEM,
		EvidenceJSON:  evidenceJSON,
		RootCert:      opts.RootCert,
		LeafCert:      leafCert,
		QuoteSHA256:   sha256Hex(quoteRaw),
		DriverVersion: opts.DriverVersion,
		VBIOSVersion:  opts.VBIOSVersion,
	}, nil
}

func ParseECPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "EC PRIVATE KEY" {
			continue
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, errors.New("no EC PRIVATE KEY block found")
}

func ParseSingleCertificatePEM(data []byte) (*x509.Certificate, error) {
	certs, err := parsePEMCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("expected exactly one certificate, got %d", len(certs))
	}
	return certs[0], nil
}

func createMockRoot(rootKey *ecdsa.PrivateKey, now time.Time, validity time.Duration) (*x509.Certificate, []byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "NVGPU Mock Test Root CA",
			Organization: []string{"nvgpu-attestation test-only"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create mock root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, der, nil
}

func createMockLeaf(leafKey, rootKey *ecdsa.PrivateKey, rootCert *x509.Certificate, fwid []byte, now time.Time, validity time.Duration) (*x509.Certificate, []byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "MOCK GH100 GSP FMC LF - NOT NVIDIA",
			Organization: []string{"nvgpu-attestation test-only"},
			Country:      []string{"ZZ"},
			SerialNumber: "MOCK-DEVICE-DO-NOT-TRUST",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{{
			Id:       hopperFWIDOID1,
			Critical: false,
			Value:    append([]byte(nil), fwid...),
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create mock leaf cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, der, nil
}

func buildMockQuote(nonce []byte, signingKey *ecdsa.PrivateKey, fwid []byte, driverVersion, vbiosVersion string, measurementCount int) ([]byte, error) {
	request := make([]byte, requestLength)
	request[0] = 0x11
	request[1] = 0xe0
	copy(request[4:36], nonce)
	request[36] = 0

	measurementRecord := buildMockMeasurementRecord(measurementCount)
	opaque, err := buildMockOpaqueFields(fwid, driverVersion, vbiosVersion)
	if err != nil {
		return nil, err
	}
	response := make([]byte, 8, 8+len(measurementRecord)+32+2+len(opaque)+signatureLength)
	response[0] = 0x11
	response[1] = 0x60
	response[4] = byte(measurementCount)
	putLE(response[5:8], uint64(len(measurementRecord)))
	response = append(response, measurementRecord...)
	responseNonce := make([]byte, 32)
	if _, err := rand.Read(responseNonce); err != nil {
		return nil, fmt.Errorf("generate mock response nonce: %w", err)
	}
	response = append(response, responseNonce...)
	opaqueLen := make([]byte, 2)
	putLE(opaqueLen, uint64(len(opaque)))
	response = append(response, opaqueLen...)
	response = append(response, opaque...)

	unsigned := append(append([]byte{}, request...), response...)
	sig, err := signP384Raw(signingKey, unsigned)
	if err != nil {
		return nil, err
	}
	return append(unsigned, sig...), nil
}

func buildMockMeasurementRecord(count int) []byte {
	var record []byte
	for i := 1; i <= count; i++ {
		seed := []byte(fmt.Sprintf("nvgpu-mock-measurement-%03d", i))
		measurement := sha512.Sum384(seed)
		payload := make([]byte, 0, 3+len(measurement))
		payload = append(payload, 0) // measurement value type/spec placeholder
		sz := make([]byte, 2)
		putLE(sz, uint64(len(measurement)))
		payload = append(payload, sz...)
		payload = append(payload, measurement[:]...)

		blockSize := make([]byte, 2)
		putLE(blockSize, uint64(len(payload)))
		record = append(record, byte(i), 0)
		record = append(record, blockSize...)
		record = append(record, payload...)
	}
	return record
}

func buildMockOpaqueFields(fwid []byte, driverVersion, vbiosVersion string) ([]byte, error) {
	vbiosRaw, err := rawVBIOSVersionForFormatted(vbiosVersion)
	if err != nil {
		return nil, err
	}
	var out []byte
	add := func(field uint16, value []byte) {
		header := make([]byte, 4)
		putLE(header[:2], uint64(field))
		putLE(header[2:], uint64(len(value)))
		out = append(out, header...)
		out = append(out, value...)
	}
	add(opaqueFieldDriverVersion, appendCString(driverVersion))
	add(opaqueFieldVBIOSVersion, vbiosRaw)
	add(opaqueFieldNVDEC0Status, []byte{0x55})
	add(15, appendCString("MOCKCHIP"))
	add(17, appendCString("MOCKPROJECT"))
	add(18, appendCString("MOCKSKU"))
	add(opaqueFieldFWID, fwid)
	ver := make([]byte, 4)
	putLE(ver, 1)
	add(opaqueFieldVersion, ver)
	add(opaqueFieldChipInfo, appendCString("MOCK GPU - NOT NVIDIA"))
	feature := make([]byte, 4)
	putLE(feature, 0)
	add(opaqueFieldFeatureFlag, feature)
	return out, nil
}

func rawVBIOSVersionForFormatted(version string) ([]byte, error) {
	compact := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(version), ".", ""))
	if compact == "" {
		compact = "96009f0001"
	}
	if len(compact) < 2 || len(compact)%2 != 0 || !isHex([]byte(compact)) {
		return nil, fmt.Errorf("vbios version must be dot-separated hex bytes, got %q", version)
	}
	// formatVBIOSVersion(raw) emits hexLE[half:] + hexLE[half-2:half].
	// Choose a harmless zero prefix that inverts that transformation for common
	// 5-byte rendered versions such as 96.00.9f.00.01.
	tailLen := len(compact) - 2
	hexLE := strings.Repeat("0", tailLen-2) + compact[tailLen:] + compact[:tailLen]
	decoded, err := hex.DecodeString(hexLE)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(decoded)-1; i < j; i, j = i+1, j-1 {
		decoded[i], decoded[j] = decoded[j], decoded[i]
	}
	if got := formatVBIOSVersion(decoded); !strings.EqualFold(strings.ReplaceAll(got, ".", ""), compact) {
		return nil, fmt.Errorf("could not encode vbios version %q; internal roundtrip produced %q", version, got)
	}
	return decoded, nil
}

func appendCString(s string) []byte {
	return append([]byte(s), 0)
}

func putLE(dst []byte, v uint64) {
	for i := range dst {
		dst[i] = byte(v >> (8 * i))
	}
}

func signP384Raw(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha512.Sum384(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign mock quote: %w", err)
	}
	sig := make([]byte, signatureLength)
	if r.BitLen() > 384 || s.BitLen() > 384 {
		return nil, errors.New("ecdsa signature component too large for P-384 raw encoding")
	}
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sig[signatureLength/2-len(rb):signatureLength/2], rb)
	copy(sig[signatureLength-len(sb):], sb)
	return sig, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}

func marshalECPrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func marshalMockEvidenceJSON(nonceHex string, quoteRaw, chainPEM []byte) ([]byte, error) {
	entries := []SerializedEvidenceEntry{{
		Arch:        "MOCK",
		Certificate: base64.StdEncoding.EncodeToString(chainPEM),
		Evidence:    base64.StdEncoding.EncodeToString(quoteRaw),
		Nonce:       strings.ToLower(nonceHex),
	}}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var _ = sha256.Size
