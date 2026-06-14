package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/museop/nvgpu-attestation/internal/nvgpu"
	"github.com/spf13/cobra"
)

const defaultSampleNonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"

type verifyConfig struct {
	quotePath        string
	certChainPath    string
	evidenceJSONPath string
	evidenceIndex    int
	allEvidence      bool
	rootsPath        string
	nonce            string
	verifyOCSP       bool
	verifyRIM        bool
	driverRIMPath    string
	vbiosRIMPath     string
	rimRootPath      string
	swidSchemaPath   string
	jsonOut          bool
	verificationTime string
	policyDrivers    []string
	policyVBIOS      []string
	policyArch       []string
	requireRIM       bool
	requireOCSP      bool
}

type rootConfig struct {
	outDir    string
	validDays int
	force     bool
	jsonOut   bool
}

type mockConfig struct {
	outDir           string
	rootKeyPath      string
	rootCertPath     string
	nonce            string
	driverVersion    string
	vbiosVersion     string
	measurementCount int
	validDays        int
	force            bool
	jsonOut          bool
}

type quietError struct{ err error }

func (e quietError) Error() string { return e.err.Error() }
func (e quietError) Unwrap() error { return e.err }

func main() {
	rootCmd := newRootCommand()
	rootCmd.SetArgs(normalizeLegacyLongFlags(os.Args[1:]))
	if err := rootCmd.Execute(); err != nil {
		var quiet quietError
		if !errors.As(err, &quiet) {
			fmt.Fprintf(os.Stderr, "command failed: %v\n", err)
		}
		os.Exit(1)
	}
}

func normalizeLegacyLongFlags(args []string) []string {
	normalized := make([]string, len(args))
	copy(normalized, args)
	for i, arg := range normalized {
		if len(arg) > 2 && arg[0] == '-' && arg[1] != '-' {
			normalized[i] = "-" + arg
		}
	}
	return normalized
}

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "nvgpu-attest",
		Short:         "Verify NVIDIA GPU attestation quotes and generate test-only mock evidence",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	verifyCfg := defaultVerifyConfig()
	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an NVGPU quote/evidence payload",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(verifyCfg)
		},
	}
	addVerifyFlags(verifyCmd, verifyCfg)

	rootGenCfg := defaultRootConfig()
	rootGenCmd := &cobra.Command{
		Use:   "root",
		Short: "Generate a test-only mock root key and certificate",
		Long: "Generate a test-only ECDSA P-384 root key and self-signed certificate for mock NVGPU evidence. " +
			"The generated root is not an NVIDIA trust anchor and must never be used for production attestation.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoot(rootGenCfg)
		},
	}
	addRootFlags(rootGenCmd, rootGenCfg)

	mockCfg := defaultMockConfig()
	mockCmd := &cobra.Command{
		Use:   "mock",
		Short: "Generate test-only mock NVGPU quote evidence under a provided root",
		Long: "Generate test-only mock NVGPU quote evidence using --root-key and --root-cert. " +
			"The output is deliberately test-scoped and must never be treated as NVIDIA attestation evidence.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMock(mockCfg)
		},
	}
	addMockFlags(mockCmd, mockCfg)

	rootCmd.AddCommand(verifyCmd, rootGenCmd, mockCmd)
	return rootCmd
}

func defaultVerifyConfig() *verifyConfig {
	return &verifyConfig{
		quotePath:      "testdata/hopperAttestationReport.txt",
		certChainPath:  "testdata/hopperCertChain.txt",
		rootsPath:      "testdata/device-root-bundle.pem",
		rimRootPath:    "testdata/verifier_RIM_root.pem",
		swidSchemaPath: "testdata/swidSchema2015.xsd",
	}
}

func defaultRootConfig() *rootConfig {
	return &rootConfig{
		outDir:    "mock-root",
		validDays: 365,
	}
}

func defaultMockConfig() *mockConfig {
	return &mockConfig{
		outDir:           "mock-evidence",
		rootKeyPath:      "mock-root/root-key.pem",
		rootCertPath:     "mock-root/root.pem",
		nonce:            nvgpu.MockDefaultNonce,
		driverVersion:    "999.0.mock",
		vbiosVersion:     "96.00.9f.00.01",
		measurementCount: 64,
		validDays:        365,
	}
}

func addVerifyFlags(cmd *cobra.Command, cfg *verifyConfig) {
	flags := cmd.Flags()
	flags.StringVar(&cfg.quotePath, "quote", cfg.quotePath, "path to an NVGPU quote file (hex text or raw bytes)")
	flags.StringVar(&cfg.certChainPath, "cert-chain", cfg.certChainPath, "path to the PEM certificate chain emitted with the quote")
	flags.StringVar(&cfg.evidenceJSONPath, "evidence-json", "", "path to NVIDIA attestation-sdk serialized JSON evidence")
	flags.IntVar(&cfg.evidenceIndex, "evidence-index", 0, "entry index inside --evidence-json when the file contains multiple evidence objects")
	flags.BoolVar(&cfg.allEvidence, "all-evidence", false, "verify every entry inside --evidence-json and emit an array of results")
	flags.StringVar(&cfg.rootsPath, "roots", cfg.rootsPath, "path to the trusted root bundle in PEM format")
	flags.StringVar(&cfg.nonce, "nonce", "", "override the 32-byte nonce used when the quote was generated, hex-encoded")
	flags.BoolVar(&cfg.verifyOCSP, "verify-ocsp", false, "query NVIDIA OCSP endpoint for certificate revocation status")
	flags.BoolVar(&cfg.verifyRIM, "verify-rim", false, "fetch or load driver/VBIOS RIMs and verify measurements against them")
	flags.StringVar(&cfg.driverRIMPath, "driver-rim", "", "optional local driver RIM (.swidtag) path; used when --verify-rim is set")
	flags.StringVar(&cfg.vbiosRIMPath, "vbios-rim", "", "optional local VBIOS RIM (.swidtag) path; used when --verify-rim is set")
	flags.StringVar(&cfg.rimRootPath, "rim-root", cfg.rimRootPath, "path to the trusted NVIDIA RIM root certificate PEM")
	flags.StringVar(&cfg.swidSchemaPath, "swid-schema", cfg.swidSchemaPath, "path to the SWID XML schema used to validate RIM files")
	flags.BoolVar(&cfg.jsonOut, "json", false, "emit JSON output")
	flags.StringVar(&cfg.verificationTime, "time", "", "verification time for certificate validity checks, RFC3339/RFC3339Nano; default is current time")
	flags.StringSliceVar(&cfg.policyDrivers, "policy-driver-version", nil, "allowed driver version for optional policy appraisal; repeat or comma-separate")
	flags.StringSliceVar(&cfg.policyVBIOS, "policy-vbios-version", nil, "allowed VBIOS version for optional policy appraisal; repeat or comma-separate")
	flags.StringSliceVar(&cfg.policyArch, "policy-arch", nil, "allowed evidence architecture for optional policy appraisal; repeat or comma-separate")
	flags.BoolVar(&cfg.requireRIM, "policy-require-rim", false, "optional policy: require RIM/measurement verification to have succeeded")
	flags.BoolVar(&cfg.requireOCSP, "policy-require-ocsp", false, "optional policy: require device OCSP checks to be present and good")
}

func addRootFlags(cmd *cobra.Command, cfg *rootConfig) {
	flags := cmd.Flags()
	flags.StringVar(&cfg.outDir, "out", cfg.outDir, "output directory for generated mock root material")
	flags.IntVar(&cfg.validDays, "valid-days", cfg.validDays, "mock root certificate validity in days")
	flags.BoolVar(&cfg.force, "force", false, "overwrite existing files in the output directory")
	flags.BoolVar(&cfg.jsonOut, "json", false, "emit JSON summary")
}

func addMockFlags(cmd *cobra.Command, cfg *mockConfig) {
	flags := cmd.Flags()
	flags.StringVar(&cfg.outDir, "out", cfg.outDir, "output directory for generated mock material")
	flags.StringVar(&cfg.rootKeyPath, "root-key", cfg.rootKeyPath, "test-only mock root private key PEM used to sign the mock leaf certificate")
	flags.StringVar(&cfg.rootCertPath, "root-cert", cfg.rootCertPath, "test-only mock root certificate PEM to include in the generated chain")
	flags.StringVar(&cfg.nonce, "nonce", cfg.nonce, "32-byte nonce to embed in the mock quote, hex-encoded")
	flags.StringVar(&cfg.driverVersion, "driver-version", cfg.driverVersion, "mock driver version stored in quote opaque data")
	flags.StringVar(&cfg.vbiosVersion, "vbios-version", cfg.vbiosVersion, "mock VBIOS version stored in quote opaque data, dot-separated hex bytes")
	flags.IntVar(&cfg.measurementCount, "measurement-count", cfg.measurementCount, "number of synthetic measurement blocks to emit, 0..255")
	flags.IntVar(&cfg.validDays, "valid-days", cfg.validDays, "mock certificate validity in days")
	flags.BoolVar(&cfg.force, "force", false, "overwrite existing files in the output directory")
	flags.BoolVar(&cfg.jsonOut, "json", false, "emit JSON summary")
}

func runVerify(cfg *verifyConfig) error {
	if cfg.allEvidence && cfg.evidenceJSONPath == "" {
		return errors.New("--all-evidence requires --evidence-json")
	}

	var (
		result       *nvgpu.Result
		batchResults []nvgpu.BatchItem
		err          error
	)
	verificationTime, err := parseVerificationTime(cfg.verificationTime)
	if err != nil {
		return err
	}

	opts := nvgpu.VerifyOptions{
		VerifyOCSP:       cfg.verifyOCSP,
		VerifyRIM:        cfg.verifyRIM,
		DriverRIMPath:    cfg.driverRIMPath,
		VBIOSRIMPath:     cfg.vbiosRIMPath,
		RIMRootPEM:       cfg.rimRootPath,
		SWIDSchemaXSD:    cfg.swidSchemaPath,
		VerificationTime: verificationTime,
		Policy: nvgpu.PolicyOptions{
			AllowedDriverVersions:          cfg.policyDrivers,
			AllowedVBIOSVersions:           cfg.policyVBIOS,
			AllowedArchitectures:           cfg.policyArch,
			RequireMeasurementVerification: cfg.requireRIM,
			RequireDeviceOCSP:              cfg.requireOCSP,
		},
	}
	if cfg.evidenceJSONPath != "" {
		if cfg.allEvidence {
			batchResults, err = nvgpu.VerifySerializedEvidenceAllFileWithOptions(cfg.evidenceJSONPath, cfg.rootsPath, cfg.nonce, opts)
		} else {
			result, err = nvgpu.VerifySerializedEvidenceFileWithOptions(cfg.evidenceJSONPath, cfg.rootsPath, cfg.evidenceIndex, cfg.nonce, opts)
		}
	} else {
		effectiveNonce := cfg.nonce
		if effectiveNonce == "" {
			effectiveNonce = defaultSampleNonce
		}
		result, err = nvgpu.VerifyFilesWithOptions(cfg.quotePath, cfg.certChainPath, cfg.rootsPath, effectiveNonce, opts)
	}

	if cfg.jsonOut {
		if cfg.allEvidence {
			ok := err == nil
			for _, item := range batchResults {
				ok = ok && item.OK
			}
			payload := struct {
				OK      bool              `json:"ok"`
				Count   int               `json:"count"`
				Results []nvgpu.BatchItem `json:"results,omitempty"`
				Error   string            `json:"error,omitempty"`
			}{OK: ok, Count: len(batchResults), Results: batchResults}
			if err != nil {
				payload.Error = err.Error()
			}
			if encodeErr := encodeJSON(os.Stdout, payload); encodeErr != nil {
				return encodeErr
			}
			if !ok {
				if err == nil {
					err = errors.New("one or more evidence entries did not verify")
				}
				return quietError{err: err}
			}
			return nil
		}
		payload := struct {
			OK     bool          `json:"ok"`
			Result *nvgpu.Result `json:"result,omitempty"`
			Error  string        `json:"error,omitempty"`
		}{OK: err == nil, Result: result}
		if err != nil {
			payload.Error = err.Error()
		}
		if encodeErr := encodeJSON(os.Stdout, payload); encodeErr != nil {
			return encodeErr
		}
		if err != nil {
			return quietError{err: err}
		}
		return nil
	}

	if cfg.allEvidence {
		allOK := err == nil
		for _, item := range batchResults {
			fmt.Printf("== evidence[%d] arch=%s ok=%v ==\n", item.Index, item.Arch, item.OK)
			if item.Result != nil {
				printResult(item.Result)
			}
			if item.Error != "" {
				fmt.Printf("error                   : %s\n", item.Error)
				allOK = false
			}
			fmt.Println()
		}
		fmt.Printf("verified entries        : %d\n", len(batchResults))
		if !allOK {
			return errors.New("one or more evidence entries did not verify")
		}
		fmt.Println("verification OK")
		return nil
	}

	if result != nil {
		printResult(result)
	}
	if err != nil {
		return err
	}
	fmt.Println("verification OK")
	return nil
}

func parseVerificationTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse --time as RFC3339: %w", err)
	}
	return parsed, nil
}

func runRoot(cfg *rootConfig) error {
	if cfg.outDir == "" {
		return errors.New("--out is required")
	}
	if cfg.validDays <= 0 {
		return errors.New("--valid-days must be positive")
	}
	bundle, err := nvgpu.GenerateMockRootBundle(nvgpu.MockRootOptions{Validity: time.Duration(cfg.validDays) * 24 * time.Hour})
	if err != nil {
		return err
	}
	if err := writeRootBundle(cfg.outDir, bundle, cfg.force); err != nil {
		return err
	}
	summary := map[string]any{
		"out_dir": cfg.outDir,
		"files": []string{
			"root-key.pem",
			"root.pem",
		},
		"mock_command": fmt.Sprintf("go run ./cmd/nvgpu-attest mock --root-key %s --root-cert %s --out mock-evidence",
			filepath.Join(cfg.outDir, "root-key.pem"), filepath.Join(cfg.outDir, "root.pem")),
		"warning": "mock/test-only root; not an NVIDIA trust anchor and not suitable for production attestation",
	}
	if cfg.jsonOut {
		return encodeJSON(os.Stdout, summary)
	}
	fmt.Println("mock root generated (TEST ONLY; not an NVIDIA trust anchor)")
	fmt.Printf("output directory : %s\n", cfg.outDir)
	fmt.Println("files:")
	for _, file := range summary["files"].([]string) {
		fmt.Printf("  - %s\n", filepath.Join(cfg.outDir, file))
	}
	fmt.Println("next:")
	fmt.Printf("  %s\n", summary["mock_command"])
	return nil
}

func runMock(cfg *mockConfig) error {
	if cfg.outDir == "" {
		return errors.New("--out is required")
	}
	if cfg.validDays <= 0 {
		return errors.New("--valid-days must be positive")
	}
	rootKey, rootCert, err := loadMockRootMaterial(cfg.rootKeyPath, cfg.rootCertPath)
	if err != nil {
		return err
	}
	bundle, err := nvgpu.GenerateMockQuoteBundleFromRoot(nvgpu.MockQuoteOptions{
		NonceHex:         cfg.nonce,
		DriverVersion:    cfg.driverVersion,
		VBIOSVersion:     cfg.vbiosVersion,
		MeasurementCount: cfg.measurementCount,
		Validity:         time.Duration(cfg.validDays) * 24 * time.Hour,
		RootKey:          rootKey,
		RootCert:         rootCert,
	})
	if err != nil {
		return err
	}
	if _, err := nvgpu.Verify(bundle.QuoteHex, bundle.CertChainPEM, bundle.RootCertPEM, bundle.NonceHex); err != nil {
		return fmt.Errorf("generated mock evidence failed standard verification path: %w", err)
	}
	if err := writeMockBundle(cfg.outDir, bundle, cfg.force); err != nil {
		return err
	}
	summary := map[string]any{
		"out_dir":        cfg.outDir,
		"nonce":          bundle.NonceHex,
		"quote_sha256":   bundle.QuoteSHA256,
		"driver_version": bundle.DriverVersion,
		"vbios_version":  bundle.VBIOSVersion,
		"root_key":       cfg.rootKeyPath,
		"root_cert":      cfg.rootCertPath,
		"files": []string{
			"nonce.txt",
			"quote.hex",
			"cert-chain.pem",
			"root.pem",
			"leaf-key.pem",
			"evidence.json",
		},
		"verify_command": fmt.Sprintf("go run ./cmd/nvgpu-attest verify --quote %s --cert-chain %s --roots %s --nonce %s --json",
			filepath.Join(cfg.outDir, "quote.hex"), filepath.Join(cfg.outDir, "cert-chain.pem"), filepath.Join(cfg.outDir, "root.pem"), bundle.NonceHex),
		"standard_verifier_checked": true,
		"warning":                   "mock/test-only evidence; not signed by NVIDIA and not suitable for production attestation",
	}
	if cfg.jsonOut {
		return encodeJSON(os.Stdout, summary)
	}
	fmt.Println("mock NVGPU evidence generated (TEST ONLY; not NVIDIA-signed)")
	fmt.Printf("output directory : %s\n", cfg.outDir)
	fmt.Printf("nonce            : %s\n", bundle.NonceHex)
	fmt.Printf("quote sha256     : %s\n", bundle.QuoteSHA256)
	fmt.Println("files:")
	for _, file := range summary["files"].([]string) {
		fmt.Printf("  - %s\n", filepath.Join(cfg.outDir, file))
	}
	fmt.Println("verify:")
	fmt.Printf("  %s\n", summary["verify_command"])
	return nil
}

func loadMockRootMaterial(rootKeyPath, rootCertPath string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	if rootKeyPath == "" {
		return nil, nil, errors.New("--root-key is required")
	}
	if rootCertPath == "" {
		return nil, nil, errors.New("--root-cert is required")
	}
	keyPEM, err := os.ReadFile(rootKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read root key: %w", err)
	}
	certPEM, err := os.ReadFile(rootCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read root cert: %w", err)
	}
	key, err := nvgpu.ParseECPrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse root key: %w", err)
	}
	cert, err := nvgpu.ParseSingleCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse root cert: %w", err)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, nil, fmt.Errorf("root cert is not self-signed or signature is invalid: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("root certificate public key is %T, want ECDSA", cert.PublicKey)
	}
	if !pub.Equal(&key.PublicKey) {
		return nil, nil, errors.New("root key does not match root certificate public key")
	}
	return key, cert, nil
}

func writeRootBundle(outDir string, bundle *nvgpu.MockRootBundle, force bool) error {
	if info, err := os.Stat(outDir); err == nil && !info.IsDir() {
		return fmt.Errorf("output path exists and is not a directory: %s", outDir)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	files := map[string][]byte{
		"root-key.pem": bundle.RootKeyPEM,
		"root.pem":     bundle.RootCertPEM,
	}
	for name := range files {
		path := filepath.Join(outDir, name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("refusing to overwrite %s without --force", path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	for name, data := range files {
		perm := os.FileMode(0o644)
		if name == "root-key.pem" {
			perm = 0o600
		}
		if err := os.WriteFile(filepath.Join(outDir, name), data, perm); err != nil {
			return err
		}
	}
	return nil
}

func writeMockBundle(outDir string, bundle *nvgpu.MockQuoteBundle, force bool) error {
	if info, err := os.Stat(outDir); err == nil && !info.IsDir() {
		return fmt.Errorf("output path exists and is not a directory: %s", outDir)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	files := map[string][]byte{
		"nonce.txt":      []byte(bundle.NonceHex + "\n"),
		"quote.hex":      bundle.QuoteHex,
		"cert-chain.pem": bundle.CertChainPEM,
		"root.pem":       bundle.RootCertPEM,
		"leaf-key.pem":   bundle.LeafKeyPEM,
		"evidence.json":  bundle.EvidenceJSON,
	}
	for name := range files {
		path := filepath.Join(outDir, name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("refusing to overwrite %s without --force", path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	for name, data := range files {
		perm := os.FileMode(0o644)
		if name == "leaf-key.pem" {
			perm = 0o600
		}
		if err := os.WriteFile(filepath.Join(outDir, name), data, perm); err != nil {
			return err
		}
	}
	return nil
}

func encodeJSON(file *os.File, v any) error {
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printResult(result *nvgpu.Result) {
	fmt.Printf("quote sha256            : %s\n", result.QuoteSHA256)
	fmt.Printf("expected request nonce  : %s\n", result.ExpectedNonce)
	fmt.Printf("quote request nonce     : %s\n", result.QuoteNonce)
	fmt.Printf("quote response nonce    : %s\n", result.ResponseNonce)
	fmt.Printf("certificate chain       : %v\n", result.CertChainVerified)
	fmt.Printf("quote signature         : %v\n", result.QuoteSignatureVerified)
	fmt.Printf("request nonce match     : %v\n", result.NonceMatches)
	fmt.Printf("FWID match              : %v\n", result.FWIDMatches)
	fmt.Printf("measurement blocks      : %d\n", result.MeasurementBlockCount)
	fmt.Printf("measurement record size : %d\n", result.MeasurementRecordLength)
	if result.VerificationTime != "" {
		fmt.Printf("verification time       : %s\n", result.VerificationTime)
	}
	if result.DriverVersion != "" {
		fmt.Printf("driver version          : %s\n", result.DriverVersion)
	}
	if result.VBIOSVersion != "" {
		fmt.Printf("vbios version           : %s\n", result.VBIOSVersion)
	}
	if result.ChipInfo != "" {
		fmt.Printf("chip info               : %s\n", result.ChipInfo)
	}
	if result.FeatureFlag != "" {
		fmt.Printf("feature flag            : %s\n", result.FeatureFlag)
	}
	if result.NVDEC0Status != "" {
		fmt.Printf("nvdec0 status           : %s\n", result.NVDEC0Status)
	}
	if result.ReportFWID != "" {
		fmt.Printf("report FWID             : %s\n", result.ReportFWID)
	}
	if result.LeafCertificateFWID != "" {
		fmt.Printf("leaf cert FWID          : %s\n", result.LeafCertificateFWID)
	}
	for i, chain := range result.VerifiedChains {
		fmt.Printf("verified chain[%d]       :\n", i)
		for _, subject := range chain {
			fmt.Printf("  - %s\n", subject)
		}
	}
	for i, check := range result.DeviceOCSPChecks {
		fmt.Printf("device ocsp[%d]          : %s (%s)\n", i, check.Status, check.CertificateSubject)
	}
	printRIM("driver", result.DriverRIM)
	printRIM("vbios", result.VBIOSRIM)
	if result.MeasurementVerification != nil {
		fmt.Printf("measurements verified   : %v\n", result.MeasurementVerification.Verified)
		fmt.Printf("runtime measurements    : %d\n", result.MeasurementVerification.RuntimeCount)
		fmt.Printf("active golden msrs      : %d\n", result.MeasurementVerification.ActiveGoldenCount)
	}
	if result.PolicyVerification != nil {
		fmt.Printf("policy verified         : %v\n", result.PolicyVerification.Verified)
		for _, check := range result.PolicyVerification.Checks {
			fmt.Printf("  - %s: %v (expected=%s actual=%s)\n", check.Name, check.OK, check.Expected, check.Actual)
		}
	}
}

func printRIM(label string, rim *nvgpu.RIMVerification) {
	if rim == nil {
		return
	}
	fmt.Printf("%s rim id              : %s\n", label, rim.ID)
	fmt.Printf("%s rim version         : %s\n", label, rim.Version)
	fmt.Printf("%s rim schema          : %v\n", label, rim.SchemaValidated)
	fmt.Printf("%s rim cert chain      : %v\n", label, rim.CertChainVerified)
	fmt.Printf("%s rim signature       : %v\n", label, rim.SignatureVerified)
	for i, check := range rim.OCSPChecks {
		fmt.Printf("%s rim ocsp[%d]         : %s (%s)\n", label, i, check.Status, check.CertificateSubject)
	}
}
