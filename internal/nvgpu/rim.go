package nvgpu

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

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

// loadAndVerifyRIM treats local files and RIM-service responses identically
// after loading: schema, version, embedded certificate chain, certificate OCSP,
// XML digest, and XML signature must all pass before measurements are trusted.
func loadAndVerifyRIM(id, source, expectedVersion, localPath string, opts VerifyOptions) (*rimDocument, *RIMVerification, error) {
	info := &RIMVerification{ID: id, Source: source}
	data, actualSource, err := loadRIMBytes(id, localPath, opts.RIMServiceURL)
	info.Source = actualSource
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
	_, err = verifyCertChain(doc.Certs, roots, rootPool, opts.VerificationTime)
	if err != nil {
		return nil, info, fmt.Errorf("%s rim cert chain verification failed: %w", source, err)
	}
	info.CertChainVerified = true
	if !opts.SkipRIMOCSP {
		checks, err := checkOCSPChain(doc.Certs, 0, opts.OCSPURL)
		info.OCSPChecks = checks
		if err != nil {
			return nil, info, fmt.Errorf("%s rim ocsp verification failed: %w", source, err)
		}
	}
	if err := verifyRIMSignature(doc); err != nil {
		return nil, info, fmt.Errorf("%s rim signature verification failed: %w", source, err)
	}
	info.SignatureVerified = true
	info.MeasurementCount = len(doc.Measurements)
	return doc, info, nil
}

func loadRIMBytes(id, localPath, serviceURL string) ([]byte, string, error) {
	if localPath != "" {
		data, err := os.ReadFile(localPath)
		return data, localPath, err
	}
	data, err := fetchRIM(id, serviceURL)
	return data, serviceURL, err
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
			if t.Name.Local == "Meta" {
				captureRIMMeta(t, doc)
			}
			if t.Name.Local == "Resource" {
				gm := parseRIMResource(t, source)
				doc.Measurements[gm.Index] = gm
			}
		case xml.EndElement:
			if len(elementStack) > 0 {
				elementStack = elementStack[:len(elementStack)-1]
			}
		case xml.CharData:
			captureRIMSignatureText(t, elementStack, doc, &x509Values)
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

func captureRIMMeta(start xml.StartElement, doc *rimDocument) {
	for _, attr := range start.Attr {
		if attr.Name.Local == "colloquialVersion" {
			doc.MetaVersion = strings.TrimSpace(attr.Value)
		}
	}
}

func parseRIMResource(start xml.StartElement, source string) goldenMeasurement {
	gm := goldenMeasurement{Source: source}
	for _, attr := range start.Attr {
		switch attr.Name.Local {
		case "index":
			fmt.Sscanf(attr.Value, "%d", &gm.Index)
		case "active":
			gm.Active = strings.EqualFold(attr.Value, "true")
		case "size":
			fmt.Sscanf(attr.Value, "%d", &gm.Size)
		default:
			if strings.HasPrefix(attr.Name.Local, "Hash") {
				gm.Alternatives = append(gm.Alternatives, strings.ToLower(strings.TrimSpace(attr.Value)))
			}
		}
	}
	return gm
}

func captureRIMSignatureText(text xml.CharData, elementStack []string, doc *rimDocument, x509Values *[]string) {
	if len(elementStack) == 0 {
		return
	}
	current := elementStack[len(elementStack)-1]
	value := strings.TrimSpace(string(text))
	if value == "" {
		return
	}
	switch current {
	case "DigestValue":
		doc.DigestValueBase64 = value
	case "SignatureValue":
		doc.SignatureValueB64 = value
	case "X509Certificate":
		*x509Values = append(*x509Values, value)
	}
}
