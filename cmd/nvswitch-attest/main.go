package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/museop/nvgpu-attestation/internal/nvgpu"
	"github.com/spf13/cobra"
)

const defaultSwitchSampleNonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"

type verifyConfig struct {
	reportPath       string
	certChainPath    string
	evidenceJSONPath string
	evidenceIndex    int
	allEvidence      bool
	rootsPath        string
	nonce            string
	verifyOCSP       bool
	verifyRIM        bool
	switchBIOSRIM    string
	rimRootPath      string
	swidSchemaPath   string
	skipRIMOCSP      bool
	jsonOut          bool
	verificationTime string
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

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "nvswitch-attest",
		Short:         "Verify NVIDIA NVSwitch attestation reports",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	verifyCfg := defaultVerifyConfig()
	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an NVSwitch report/evidence payload",
		Long: "Verify an NVSwitch attestation report/evidence payload. " +
			"Mandatory local checks include nonce, report signature, and device certificate chain. " +
			"Optional --verify-ocsp and --verify-rim add revocation and BIOS RIM/measurement appraisal.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(verifyCfg)
		},
	}
	addVerifyFlags(verifyCmd, verifyCfg)

	rootCmd.AddCommand(verifyCmd)
	return rootCmd
}

func defaultVerifyConfig() *verifyConfig {
	return &verifyConfig{
		reportPath:     "testdata/switchAttestationReport.txt",
		certChainPath:  "testdata/switchCertChain.txt",
		rootsPath:      "testdata/device-root-bundle.pem",
		switchBIOSRIM:  "testdata/switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml",
		rimRootPath:    "testdata/verifier_RIM_root.pem",
		swidSchemaPath: "testdata/swidSchema2015.xsd",
	}
}

func addVerifyFlags(cmd *cobra.Command, cfg *verifyConfig) {
	flags := cmd.Flags()
	flags.StringVar(&cfg.reportPath, "report", cfg.reportPath, "path to an NVSwitch attestation report file (hex text or raw bytes)")
	flags.StringVar(&cfg.certChainPath, "cert-chain", cfg.certChainPath, "path to the PEM certificate chain emitted with the report")
	flags.StringVar(&cfg.evidenceJSONPath, "evidence-json", "", "path to NVIDIA attestation-sdk serialized NVSwitch JSON evidence")
	flags.IntVar(&cfg.evidenceIndex, "evidence-index", 0, "entry index inside --evidence-json when the file contains multiple evidence objects")
	flags.BoolVar(&cfg.allEvidence, "all-evidence", false, "verify every entry inside --evidence-json and emit an array of results")
	flags.StringVar(&cfg.rootsPath, "roots", cfg.rootsPath, "path to the trusted NVIDIA device root bundle in PEM format")
	flags.StringVar(&cfg.nonce, "nonce", "", "override the 32-byte nonce used when the report was generated, hex-encoded")
	flags.BoolVar(&cfg.verifyOCSP, "verify-ocsp", false, "query NVIDIA OCSP endpoint for certificate revocation status")
	flags.BoolVar(&cfg.verifyRIM, "verify-rim", false, "load/fetch switch BIOS RIM and verify measurements against it")
	flags.StringVar(&cfg.switchBIOSRIM, "switch-bios-rim", cfg.switchBIOSRIM, "optional local NVSwitch BIOS RIM XML path; used when --verify-rim is set")
	flags.StringVar(&cfg.rimRootPath, "rim-root", cfg.rimRootPath, "path to the trusted NVIDIA RIM root certificate PEM")
	flags.StringVar(&cfg.swidSchemaPath, "swid-schema", cfg.swidSchemaPath, "path to the SWID XML schema used to validate RIM files")
	flags.BoolVar(&cfg.skipRIMOCSP, "skip-rim-ocsp", false, "skip RIM certificate OCSP checks; useful for NVIDIA unit-test/staging sample RIMs, not recommended for production")
	flags.BoolVar(&cfg.jsonOut, "json", false, "emit JSON output")
	flags.StringVar(&cfg.verificationTime, "time", "", "verification time for certificate validity checks, RFC3339/RFC3339Nano; default is current time")
}

func runVerify(cfg *verifyConfig) error {
	if cfg.allEvidence && cfg.evidenceJSONPath == "" {
		return errors.New("--all-evidence requires --evidence-json")
	}
	verificationTime, err := parseVerificationTime(cfg.verificationTime)
	if err != nil {
		return err
	}
	opts := nvgpu.SwitchVerifyOptions{
		VerifyOCSP:        cfg.verifyOCSP,
		VerifyRIM:         cfg.verifyRIM,
		SwitchBIOSRIMPath: cfg.switchBIOSRIM,
		RIMRootPEM:        cfg.rimRootPath,
		SWIDSchemaXSD:     cfg.swidSchemaPath,
		SkipRIMOCSP:       cfg.skipRIMOCSP,
		VerificationTime:  verificationTime,
	}

	var (
		result       *nvgpu.SwitchResult
		batchResults []nvgpu.SwitchBatchItem
	)
	if cfg.evidenceJSONPath != "" {
		if cfg.allEvidence {
			batchResults, err = nvgpu.VerifySwitchSerializedEvidenceAllFileWithOptions(cfg.evidenceJSONPath, cfg.rootsPath, cfg.nonce, opts)
		} else {
			result, err = nvgpu.VerifySwitchSerializedEvidenceFileWithOptions(cfg.evidenceJSONPath, cfg.rootsPath, cfg.evidenceIndex, cfg.nonce, opts)
		}
	} else {
		effectiveNonce := cfg.nonce
		if effectiveNonce == "" {
			effectiveNonce = defaultSwitchSampleNonce
		}
		result, err = nvgpu.VerifySwitchFilesWithOptions(cfg.reportPath, cfg.certChainPath, cfg.rootsPath, effectiveNonce, opts)
	}

	if cfg.jsonOut {
		if cfg.allEvidence {
			ok := err == nil
			for _, item := range batchResults {
				ok = ok && item.OK
			}
			payload := struct {
				OK      bool                    `json:"ok"`
				Count   int                     `json:"count"`
				Results []nvgpu.SwitchBatchItem `json:"results,omitempty"`
				Error   string                  `json:"error,omitempty"`
			}{OK: ok, Count: len(batchResults), Results: batchResults}
			if err != nil {
				payload.Error = err.Error()
			}
			if encodeErr := encodeJSON(os.Stdout, payload); encodeErr != nil {
				return encodeErr
			}
			if !ok {
				if err == nil {
					err = errors.New("one or more switch evidence entries did not verify")
				}
				return quietError{err: err}
			}
			return nil
		}
		payload := struct {
			OK     bool                `json:"ok"`
			Result *nvgpu.SwitchResult `json:"result,omitempty"`
			Error  string              `json:"error,omitempty"`
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
			fmt.Printf("== switch evidence[%d] arch=%s ok=%v ==\n", item.Index, item.Arch, item.OK)
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
			return errors.New("one or more switch evidence entries did not verify")
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

func printResult(result *nvgpu.SwitchResult) {
	fmt.Printf("report sha256           : %s\n", result.ReportSHA256)
	fmt.Printf("input format            : %s\n", result.InputFormat)
	if result.EvidenceArch != "" {
		fmt.Printf("evidence arch           : %s\n", result.EvidenceArch)
	}
	fmt.Printf("cert chain verified     : %v\n", result.CertChainVerified)
	fmt.Printf("report signature        : %v\n", result.ReportSignatureVerified)
	fmt.Printf("nonce matches           : %v\n", result.NonceMatches)
	fmt.Printf("measurement blocks      : %d\n", result.MeasurementBlockCount)
	fmt.Printf("measurement record len  : %d\n", result.MeasurementRecordLength)
	fmt.Printf("switch BIOS version     : %s\n", result.SwitchBIOSVersion)
	fmt.Printf("switch BIOS RIM ID      : %s\n", result.SwitchBIOSRIMID)
	if result.SwitchPDI != "" {
		fmt.Printf("switch PDI              : %s\n", result.SwitchPDI)
	}
	fmt.Printf("FWID present            : %v\n", result.FWIDPresent)
	if result.FWIDPresent {
		fmt.Printf("FWID matches            : %v\n", result.FWIDMatches)
	}
	fmt.Printf("leaf subject            : %s\n", result.LeafSubject)
	if result.MeasurementVerification != nil {
		fmt.Printf("measurements verified   : %v\n", result.MeasurementVerification.Verified)
		fmt.Printf("active golden count     : %d\n", result.MeasurementVerification.ActiveGoldenCount)
	}
	if result.SwitchBIOSRIM != nil {
		fmt.Printf("switch BIOS RIM source  : %s\n", result.SwitchBIOSRIM.Source)
		fmt.Printf("switch BIOS RIM sig     : %v\n", result.SwitchBIOSRIM.SignatureVerified)
	}
	if len(result.DeviceOCSPChecks) > 0 {
		fmt.Printf("device OCSP checks      : %d\n", len(result.DeviceOCSPChecks))
	}
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

func encodeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
