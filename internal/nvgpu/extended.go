package nvgpu

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	defaultOCSPURL       = "https://ocsp.ndis.nvidia.com"
	defaultRIMServiceURL = "https://rim.attestation.nvidia.com/v1/rim/"
)

type VerifyOptions struct {
	VerifyOCSP    bool
	VerifyRIM     bool
	OCSPURL       string
	RIMServiceURL string
	DriverRIMPath string
	VBIOSRIMPath  string
	RIMRootPEM    string
	SWIDSchemaXSD string
}

type OCSPCheck struct {
	CertificateSubject string `json:"certificate_subject"`
	IssuerSubject      string `json:"issuer_subject"`
	Status             string `json:"status"`
	ThisUpdate         string `json:"this_update,omitempty"`
	NextUpdate         string `json:"next_update,omitempty"`
}

type RIMVerification struct {
	ID                string      `json:"id,omitempty"`
	Source            string      `json:"source"`
	Version           string      `json:"version,omitempty"`
	CertChainVerified bool        `json:"cert_chain_verified"`
	SignatureVerified bool        `json:"signature_verified"`
	SchemaValidated   bool        `json:"schema_validated"`
	OCSPChecks        []OCSPCheck `json:"ocsp_checks,omitempty"`
	MeasurementCount  int         `json:"measurement_count,omitempty"`
	FetchedSHA256     string      `json:"fetched_sha256,omitempty"`
}

type MeasurementMismatch struct {
	Index  int    `json:"index"`
	Source string `json:"source"`
}

type MeasurementSummary struct {
	Verified           bool                  `json:"verified"`
	RuntimeCount       int                   `json:"runtime_count"`
	ActiveGoldenCount  int                   `json:"active_golden_count"`
	Mismatched         []MeasurementMismatch `json:"mismatched,omitempty"`
	SkippedMeasurement []int                 `json:"skipped_measurements,omitempty"`
}

type rimDocument struct {
	Raw               []byte
	MetaVersion       string
	DigestValueBase64 string
	SignatureValueB64 string
	Certs             []*x509.Certificate
	Measurements      map[int]goldenMeasurement
}

type goldenMeasurement struct {
	Index        int
	Source       string
	Active       bool
	Size         int
	Alternatives []string
}

func VerifyFilesWithOptions(quotePath, certChainPath, rootsPath, expectedNonceHex string, opts VerifyOptions) (*Result, error) {
	result, quote, chain, err := verifyFilesDetailed(quotePath, certChainPath, rootsPath, expectedNonceHex)
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
	entry := entries[index]
	res, quote, chain, err := verifySerializedEntryDetailed(entry, rootsData, expectedNonceHex)
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
		result, quote, chain, verifyErr := verifySerializedEntryDetailed(entry, rootsData, expectedNonceHex)
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

func verifyFilesDetailed(quotePath, certChainPath, rootsPath, expectedNonceHex string) (*Result, *Quote, []*x509.Certificate, error) {
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
	return verifyDetailed(quoteData, chainData, rootsData, expectedNonceHex, "split-files", "")
}

func verifySerializedEntryDetailed(entry SerializedEvidenceEntry, rootsPEM []byte, expectedNonceHex string) (*Result, *Quote, []*x509.Certificate, error) {
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
	return verifyDetailed(quoteRaw, certChainPEM, rootsPEM, nonceHex, "serialized-json", entry.Arch)
}

func verifyDetailed(quoteInput, certChainPEM, rootsPEM []byte, expectedNonceHex, inputFormat, evidenceArch string) (*Result, *Quote, []*x509.Certificate, error) {
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
	verifiedChains, err := verifyCertChain(chain, roots, rootPool)
	if err != nil {
		return nil, nil, chain, err
	}
	leaf := chain[0]
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
	if !result.NonceMatches {
		return result, quote, chain, fmt.Errorf("nonce mismatch: expected %s, quote carries %s", result.ExpectedNonce, result.QuoteNonce)
	}
	if sigOK, err := verifyQuoteSignature(quote.Raw, quote.Response.Signature, leaf.PublicKey); err != nil {
		return result, quote, chain, err
	} else {
		result.QuoteSignatureVerified = sigOK
	}
	if !result.QuoteSignatureVerified {
		return result, quote, chain, errors.New("quote signature verification failed")
	}
	populateOpaqueSummary(result, quote.Response.OpaqueFields)
	leafFWID, err := extractLeafFWID(leaf)
	if err != nil {
		return result, quote, chain, err
	}
	result.LeafCertificateFWID = leafFWID
	result.ReportFWID = hex.EncodeToString(quote.Response.OpaqueFields[opaqueFieldFWID])
	result.FWIDMatches = result.ReportFWID != "" && strings.EqualFold(result.ReportFWID, result.LeafCertificateFWID)
	if result.ReportFWID == "" {
		result.FWIDMatches = false
		return result, quote, chain, errors.New("quote does not contain FWID opaque field")
	}
	if !result.FWIDMatches {
		return result, quote, chain, fmt.Errorf("fwid mismatch: report=%s leaf=%s", result.ReportFWID, result.LeafCertificateFWID)
	}
	return result, quote, chain, nil
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
	return nil
}

func checkOCSPChain(chain []*x509.Certificate, startIndex int, ocspURL string) ([]OCSPCheck, error) {
	if startIndex < 0 {
		startIndex = 0
	}
	if len(chain) < 2 || startIndex >= len(chain)-1 {
		return nil, nil
	}
	checks := make([]OCSPCheck, 0, len(chain)-1-startIndex)
	for i := startIndex; i < len(chain)-1; i++ {
		check, err := queryOCSP(chain[i], chain[i+1], ocspURL)
		checks = append(checks, check)
		if err != nil {
			return checks, err
		}
		if check.Status != "good" && check.Status != "revoked/certificateHold" {
			return checks, fmt.Errorf("ocsp status for %s is %s", check.CertificateSubject, check.Status)
		}
	}
	return checks, nil
}

func queryOCSP(cert, issuer *x509.Certificate, ocspURL string) (OCSPCheck, error) {
	check := OCSPCheck{CertificateSubject: cert.Subject.String(), IssuerSubject: issuer.Subject.String()}
	certFile, err := writeTempPEM(cert)
	if err != nil {
		return check, err
	}
	defer os.Remove(certFile)
	issuerFile, err := writeTempPEM(issuer)
	if err != nil {
		return check, err
	}
	defer os.Remove(issuerFile)
	cmd := exec.Command("openssl", "ocsp", "-issuer", issuerFile, "-cert", certFile, "-url", ocspURL, "-noverify", "-timeout", "10")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return check, fmt.Errorf("openssl ocsp failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return check, errors.New("empty OCSP response")
	}
	statusLine := strings.TrimSpace(lines[0])
	parts := strings.SplitN(statusLine, ":", 2)
	if len(parts) != 2 {
		return check, fmt.Errorf("unexpected OCSP output: %s", statusLine)
	}
	check.Status = strings.TrimSpace(parts[1])
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "This Update:") {
			check.ThisUpdate = strings.TrimSpace(strings.TrimPrefix(line, "This Update:"))
		}
		if strings.HasPrefix(line, "Next Update:") {
			check.NextUpdate = strings.TrimSpace(strings.TrimPrefix(line, "Next Update:"))
		}
		if strings.Contains(line, "certificateHold") {
			check.Status = "revoked/certificateHold"
		}
	}
	return check, nil
}

func verifyRIMsAndMeasurements(result *Result, quote *Quote, opts VerifyOptions) (*MeasurementSummary, *RIMVerification, *RIMVerification, error) {
	driverID := "NV_GPU_DRIVER_GH100_" + result.DriverVersion
	vbiosID := strings.ToUpper("NV_GPU_VBIOS_" + decodeCString(quote.Response.OpaqueFields[17]) + "_" + decodeCString(quote.Response.OpaqueFields[18]) + "_" + decodeCString(quote.Response.OpaqueFields[15]) + "_" + strings.ReplaceAll(result.VBIOSVersion, ".", ""))
	driverDoc, driverInfo, err := loadAndVerifyRIM(driverID, "driver", result.DriverVersion, opts.DriverRIMPath, opts)
	if err != nil {
		return nil, driverInfo, nil, err
	}
	vbiosDoc, vbiosInfo, err := loadAndVerifyRIM(vbiosID, "vbios", result.VBIOSVersion, opts.VBIOSRIMPath, opts)
	if err != nil {
		return nil, driverInfo, vbiosInfo, err
	}
	summary, err := compareMeasurements(quote, driverDoc, vbiosDoc, result.NVDEC0Status == "disabled")
	if err != nil {
		return summary, driverInfo, vbiosInfo, err
	}
	return summary, driverInfo, vbiosInfo, nil
}

func loadAndVerifyRIM(id, source, expectedVersion, localPath string, opts VerifyOptions) (*rimDocument, *RIMVerification, error) {
	info := &RIMVerification{ID: id, Source: source}
	var data []byte
	var err error
	if localPath != "" {
		data, err = os.ReadFile(localPath)
		info.Source = localPath
	} else {
		data, err = fetchRIM(id, opts.RIMServiceURL)
		info.Source = opts.RIMServiceURL
	}
	if err != nil {
		return nil, info, err
	}
	info.FetchedSHA256 = sha256Hex(data)
	doc, err := parseRIM(data, source)
	if err != nil {
		return nil, info, err
	}
	info.Version = doc.MetaVersion
	if opts.SWIDSchemaXSD != "" {
		if err := validateRIMSchema(data, opts.SWIDSchemaXSD); err != nil {
			return nil, info, err
		}
		info.SchemaValidated = true
	}
	if expectedVersion != "" && !strings.EqualFold(strings.TrimSpace(doc.MetaVersion), strings.TrimSpace(expectedVersion)) {
		return nil, info, fmt.Errorf("%s rim version mismatch: rim=%s expected=%s", source, doc.MetaVersion, expectedVersion)
	}
	if opts.RIMRootPEM == "" {
		return nil, info, errors.New("rim root certificate path is required for rim verification")
	}
	rootPEM, err := os.ReadFile(opts.RIMRootPEM)
	if err != nil {
		return nil, info, fmt.Errorf("read rim root pem: %w", err)
	}
	roots, rootPool, err := parseRootBundle(rootPEM)
	if err != nil {
		return nil, info, fmt.Errorf("parse rim root bundle: %w", err)
	}
	_, err = verifyCertChain(doc.Certs, roots, rootPool)
	if err != nil {
		return nil, info, fmt.Errorf("%s rim cert chain verification failed: %w", source, err)
	}
	info.CertChainVerified = true
	checks, err := checkOCSPChain(doc.Certs, 0, opts.OCSPURL)
	info.OCSPChecks = checks
	if err != nil {
		return nil, info, fmt.Errorf("%s rim ocsp verification failed: %w", source, err)
	}
	if err := verifyRIMSignature(doc); err != nil {
		return nil, info, fmt.Errorf("%s rim signature verification failed: %w", source, err)
	}
	info.SignatureVerified = true
	info.MeasurementCount = len(doc.Measurements)
	return doc, info, nil
}

func fetchRIM(id, baseURL string) ([]byte, error) {
	resp, err := http.Get(strings.TrimRight(baseURL, "/") + "/" + id)
	if err != nil {
		return nil, fmt.Errorf("fetch rim: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("fetch rim http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		RIM string `json:"rim"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode rim json: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(payload.RIM)
	if err != nil {
		return nil, fmt.Errorf("decode rim base64: %w", err)
	}
	return data, nil
}

func validateRIMSchema(data []byte, xsdPath string) error {
	xmlFile, err := writeTempBytes(data, ".swidtag")
	if err != nil {
		return err
	}
	defer os.Remove(xmlFile)
	cmd := exec.Command("xmllint", "--noout", "--schema", xsdPath, xmlFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xmllint schema validation failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func parseRIM(data []byte, source string) (*rimDocument, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	doc := &rimDocument{Raw: data, Measurements: map[int]goldenMeasurement{}}
	var elementStack []string
	var x509Values []string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse rim xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			elementStack = append(elementStack, t.Name.Local)
			switch t.Name.Local {
			case "Meta":
				for _, a := range t.Attr {
					if a.Name.Local == "colloquialVersion" {
						doc.MetaVersion = strings.TrimSpace(a.Value)
					}
				}
			case "Resource":
				gm := goldenMeasurement{Source: source}
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "index":
						fmt.Sscanf(a.Value, "%d", &gm.Index)
					case "active":
						gm.Active = strings.EqualFold(a.Value, "true")
					case "size":
						fmt.Sscanf(a.Value, "%d", &gm.Size)
					default:
						if strings.HasPrefix(a.Name.Local, "Hash") {
							gm.Alternatives = append(gm.Alternatives, strings.ToLower(strings.TrimSpace(a.Value)))
						}
					}
				}
				doc.Measurements[gm.Index] = gm
			}
		case xml.EndElement:
			if len(elementStack) > 0 {
				elementStack = elementStack[:len(elementStack)-1]
			}
		case xml.CharData:
			if len(elementStack) == 0 {
				continue
			}
			current := elementStack[len(elementStack)-1]
			text := strings.TrimSpace(string(t))
			if text == "" {
				continue
			}
			switch current {
			case "DigestValue":
				doc.DigestValueBase64 = text
			case "SignatureValue":
				doc.SignatureValueB64 = text
			case "X509Certificate":
				x509Values = append(x509Values, text)
			}
		}
	}
	for _, val := range x509Values {
		certPEM := []byte("-----BEGIN CERTIFICATE-----\n" + strings.ReplaceAll(strings.TrimSpace(val), " ", "") + "\n-----END CERTIFICATE-----\n")
		certs, err := parsePEMCertificates(certPEM)
		if err != nil {
			return nil, err
		}
		doc.Certs = append(doc.Certs, certs...)
	}
	if len(doc.Certs) == 0 {
		return nil, errors.New("no x509 certificates found in rim")
	}
	if doc.DigestValueBase64 == "" || doc.SignatureValueB64 == "" {
		return nil, errors.New("rim signature fields missing")
	}
	return doc, nil
}

var (
	reSignatureOpen  = regexp.MustCompile(`<([A-Za-z0-9_]+:)?Signature\b[\s\S]*?</([A-Za-z0-9_]+:)?Signature>`)
	reSignedInfo     = regexp.MustCompile(`<([A-Za-z0-9_]+:)?SignedInfo\b[\s\S]*?</([A-Za-z0-9_]+:)?SignedInfo>`)
	reSignedInfoOpen = regexp.MustCompile(`<([A-Za-z0-9_]+:)?SignedInfo\b`)
	reRootOpen       = regexp.MustCompile(`<SoftwareIdentity\b([^>]*)>`)
	reSigStart       = regexp.MustCompile(`<([A-Za-z0-9_]+:)?Signature\b([^>]*)>`)
	reXMLNS          = regexp.MustCompile(`xmlns(?::[A-Za-z0-9_]+)?="[^"]+"`)
)

func verifyRIMSignature(doc *rimDocument) error {
	withoutSig := reSignatureOpen.ReplaceAll(doc.Raw, nil)
	c14nDocument, err := canonicalizeXML(withoutSig)
	if err != nil {
		return err
	}
	expectedDigest, err := base64.StdEncoding.DecodeString(doc.DigestValueBase64)
	if err != nil {
		return fmt.Errorf("decode rim digest: %w", err)
	}
	digest := sha512.Sum384(c14nDocument)
	if !bytes.Equal(digest[:], expectedDigest) {
		return errors.New("rim digest mismatch")
	}
	signedInfo := reSignedInfo.Find(doc.Raw)
	if len(signedInfo) == 0 {
		return errors.New("signedinfo element not found")
	}
	xmlnsDecls := collectXMLNSDecls(doc.Raw)
	if len(xmlnsDecls) > 0 {
		decls := " " + strings.Join(xmlnsDecls, " ")
		signedInfo = reSignedInfoOpen.ReplaceAll(signedInfo, []byte(`${0}`+decls))
	}
	c14nSignedInfo, err := canonicalizeXML(signedInfo)
	if err != nil {
		return err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(doc.SignatureValueB64)
	if err != nil {
		return fmt.Errorf("decode rim signature value: %w", err)
	}
	pub, ok := doc.Certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported rim public key type %T", doc.Certs[0].PublicKey)
	}
	if len(sigBytes)%2 != 0 {
		return errors.New("unexpected rim ecdsa signature length")
	}
	hash := sha512.Sum384(c14nSignedInfo)
	r := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
	s := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("rim ecdsa signature invalid")
	}
	return nil
}

func collectXMLNSDecls(data []byte) []string {
	var rawDecls string
	if m := reRootOpen.FindSubmatch(data); len(m) == 2 {
		rawDecls += " " + string(m[1])
	}
	if m := reSigStart.FindSubmatch(data); len(m) == 3 {
		rawDecls += " " + string(m[2])
	}
	matches := reXMLNS.FindAllString(rawDecls, -1)
	seen := map[string]bool{}
	decls := make([]string, 0, len(matches))
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			decls = append(decls, m)
		}
	}
	sort.Strings(decls)
	return decls
}

func canonicalizeXML(data []byte) ([]byte, error) {
	tmp, err := writeTempBytes(data, ".xml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	cmd := exec.Command("xmllint", "--c14n11", tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("xmllint c14n11 failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func compareMeasurements(quote *Quote, driverDoc, vbiosDoc *rimDocument, nvdecDisabled bool) (*MeasurementSummary, error) {
	runtime := quote.Response.getMeasurements()
	golden := map[int]goldenMeasurement{}
	for idx, gm := range driverDoc.Measurements {
		if gm.Active {
			golden[idx] = gm
		}
	}
	for idx, gm := range vbiosDoc.Measurements {
		if !gm.Active {
			continue
		}
		if _, exists := golden[idx]; exists {
			return &MeasurementSummary{}, fmt.Errorf("driver and vbios rim share active measurement index %d", idx)
		}
		golden[idx] = gm
	}
	keys := make([]int, 0, len(golden))
	for k := range golden {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	summary := &MeasurementSummary{RuntimeCount: len(runtime), ActiveGoldenCount: len(golden)}
	for _, idx := range keys {
		if idx == 35 && nvdecDisabled {
			summary.SkippedMeasurement = append(summary.SkippedMeasurement, idx)
			continue
		}
		if idx < 0 || idx >= len(runtime) {
			summary.Mismatched = append(summary.Mismatched, MeasurementMismatch{Index: idx, Source: golden[idx].Source})
			continue
		}
		gm := golden[idx]
		matched := false
		for _, alt := range gm.Alternatives {
			if strings.EqualFold(alt, runtime[idx]) && gm.Size*2 == len(runtime[idx]) {
				matched = true
				break
			}
		}
		if !matched {
			summary.Mismatched = append(summary.Mismatched, MeasurementMismatch{Index: idx, Source: gm.Source})
		}
	}
	summary.Verified = len(summary.Mismatched) == 0
	if !summary.Verified {
		return summary, errors.New("runtime measurements do not match golden measurements")
	}
	return summary, nil
}

func (r Response) getMeasurements() []string {
	record := r.MeasurementRecord
	count := int(r.MeasurementBlockCount)
	measurements := make([]string, count)
	for i := 0; i < len(record); {
		if len(record[i:]) < 4 {
			break
		}
		idx := int(record[i])
		i++
		_ = record[i]
		i++
		size := int(readLE(record[i : i+2]))
		i += 2
		if len(record[i:]) < size {
			break
		}
		block := record[i : i+size]
		i += size
		if len(block) < 3 || idx <= 0 || idx > count {
			continue
		}
		valSize := int(readLE(block[1:3]))
		if len(block) < 3+valSize {
			continue
		}
		measurements[idx-1] = hex.EncodeToString(block[3 : 3+valSize])
	}
	return measurements
}

func writeTempPEM(cert *x509.Certificate) (string, error) {
	return writeTempBytes(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), ".pem")
}

func writeTempBytes(data []byte, suffix string) (string, error) {
	f, err := os.CreateTemp("", "nvgpu-*"+suffix)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return filepath.Clean(f.Name()), nil
}

var _ = asn1.NullRawValue
