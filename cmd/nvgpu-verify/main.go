package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/museop/nvgpu-attestation/internal/nvgpu"
)

func main() {
	const defaultSampleNonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"

	quotePath := flag.String("quote", "testdata/hopperAttestationReport.txt", "path to an NVGPU quote file (hex text or raw bytes)")
	certChainPath := flag.String("cert-chain", "testdata/hopperCertChain.txt", "path to the PEM certificate chain emitted with the quote")
	evidenceJSONPath := flag.String("evidence-json", "", "path to NVIDIA attestation-sdk serialized JSON evidence")
	evidenceIndex := flag.Int("evidence-index", 0, "entry index inside -evidence-json when the file contains multiple evidence objects")
	allEvidence := flag.Bool("all-evidence", false, "verify every entry inside -evidence-json and emit an array of results")
	rootsPath := flag.String("roots", "testdata/device-root-bundle.pem", "path to the trusted NVIDIA device root bundle in PEM format")
	nonce := flag.String("nonce", "", "override the 32-byte nonce used when the quote was generated, hex-encoded")
	verifyOCSP := flag.Bool("verify-ocsp", false, "query NVIDIA OCSP endpoint for certificate revocation status")
	verifyRIM := flag.Bool("verify-rim", false, "fetch or load driver/VBIOS RIMs and verify measurements against them")
	driverRIMPath := flag.String("driver-rim", "", "optional local driver RIM (.swidtag) path; used when -verify-rim is set")
	vbiosRIMPath := flag.String("vbios-rim", "", "optional local VBIOS RIM (.swidtag) path; used when -verify-rim is set")
	rimRootPath := flag.String("rim-root", "testdata/verifier_RIM_root.pem", "path to the trusted NVIDIA RIM root certificate PEM")
	swidSchemaPath := flag.String("swid-schema", "testdata/swidSchema2015.xsd", "path to the SWID XML schema used to validate RIM files")
	jsonOut := flag.Bool("json", false, "emit JSON output")
	flag.Parse()

	if *allEvidence && *evidenceJSONPath == "" {
		fmt.Fprintln(os.Stderr, "verification failed: -all-evidence requires -evidence-json")
		os.Exit(1)
	}

	var (
		result       *nvgpu.Result
		batchResults []nvgpu.BatchItem
		err          error
	)
	opts := nvgpu.VerifyOptions{
		VerifyOCSP:    *verifyOCSP,
		VerifyRIM:     *verifyRIM,
		DriverRIMPath: *driverRIMPath,
		VBIOSRIMPath:  *vbiosRIMPath,
		RIMRootPEM:    *rimRootPath,
		SWIDSchemaXSD: *swidSchemaPath,
	}
	if *evidenceJSONPath != "" {
		if *allEvidence {
			batchResults, err = nvgpu.VerifySerializedEvidenceAllFileWithOptions(*evidenceJSONPath, *rootsPath, *nonce, opts)
		} else {
			result, err = nvgpu.VerifySerializedEvidenceFileWithOptions(*evidenceJSONPath, *rootsPath, *evidenceIndex, *nonce, opts)
		}
	} else {
		effectiveNonce := *nonce
		if effectiveNonce == "" {
			effectiveNonce = defaultSampleNonce
		}
		result, err = nvgpu.VerifyFilesWithOptions(*quotePath, *certChainPath, *rootsPath, effectiveNonce, opts)
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if *allEvidence {
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
			must(enc.Encode(payload))
			if !ok {
				os.Exit(1)
			}
			return
		}
		payload := struct {
			OK     bool          `json:"ok"`
			Result *nvgpu.Result `json:"result,omitempty"`
			Error  string        `json:"error,omitempty"`
		}{OK: err == nil, Result: result}
		if err != nil {
			payload.Error = err.Error()
		}
		must(enc.Encode(payload))
		if err != nil {
			os.Exit(1)
		}
		return
	}

	if *allEvidence {
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
			fmt.Fprintln(os.Stderr, "verification failed: one or more evidence entries did not verify")
			os.Exit(1)
		}
		fmt.Println("verification OK")
		return
	}

	if result != nil {
		printResult(result)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("verification OK")
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

var _ = hex.EncodeToString

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
