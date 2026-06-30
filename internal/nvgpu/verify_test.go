package nvgpu

import (
	"os"
	"strings"
	"testing"
)

const sampleNonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
const sdkSampleNonce = "e97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576"
const switchSampleNonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"

func TestVerifySampleQuote(t *testing.T) {
	result, err := VerifyFiles("../../testdata/hopperAttestationReport.txt", "../../testdata/hopperCertChain.txt", "../../testdata/device-root-bundle.pem", sampleNonce)
	if err != nil {
		t.Fatalf("VerifyFiles() error = %v", err)
	}
	if !result.CertChainVerified || !result.QuoteSignatureVerified || !result.NonceMatches || !result.FWIDMatches {
		t.Fatalf("unexpected result: %+v", result)
	}
	if got, want := result.DriverVersion, "550.90.07"; got != want {
		t.Fatalf("DriverVersion = %q, want %q", got, want)
	}
	if got, want := result.MeasurementBlockCount, 64; got != want {
		t.Fatalf("MeasurementBlockCount = %d, want %d", got, want)
	}
	if result.VBIOSVersion == "" {
		t.Fatal("VBIOSVersion should not be empty")
	}
}

func TestVerifySampleQuoteRejectsWrongNonce(t *testing.T) {
	result, err := VerifyFiles("../../testdata/hopperAttestationReport.txt", "../../testdata/hopperCertChain.txt", "../../testdata/device-root-bundle.pem", "001d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb")
	if err == nil {
		t.Fatal("VerifyFiles() unexpectedly succeeded")
	}
	if result == nil || result.NonceMatches {
		t.Fatalf("expected nonce mismatch result, got %+v", result)
	}
}

func TestVerifySerializedEvidenceSingle(t *testing.T) {
	result, err := VerifySerializedEvidenceFile("../../testdata/hopper_evidence.json", "../../testdata/device-root-bundle.pem", 0, "")
	if err != nil {
		t.Fatalf("VerifySerializedEvidenceFile() error = %v", err)
	}
	if !result.CertChainVerified || !result.QuoteSignatureVerified || !result.NonceMatches || !result.FWIDMatches {
		t.Fatalf("unexpected result: %+v", result)
	}
	if got, want := result.EvidenceArch, "HOPPER"; got != want {
		t.Fatalf("EvidenceArch = %q, want %q", got, want)
	}
	if got, want := result.ExpectedNonce, sdkSampleNonce; got != want {
		t.Fatalf("ExpectedNonce = %q, want %q", got, want)
	}
	if got, want := result.InputFormat, "serialized-json"; got != want {
		t.Fatalf("InputFormat = %q, want %q", got, want)
	}
}

func TestVerifySerializedEvidenceMulti(t *testing.T) {
	for i := 0; i < 4; i++ {
		result, err := VerifySerializedEvidenceFile("../../testdata/multi_gpu_hopper.json", "../../testdata/device-root-bundle.pem", i, "")
		if err != nil {
			t.Fatalf("VerifySerializedEvidenceFile(index=%d) error = %v", i, err)
		}
		if !result.NonceMatches || !result.QuoteSignatureVerified || !result.CertChainVerified {
			t.Fatalf("unexpected result at index %d: %+v", i, result)
		}
	}
}

func TestVerifySerializedEvidenceAll(t *testing.T) {
	items, err := VerifySerializedEvidenceAllFile("../../testdata/multi_gpu_hopper.json", "../../testdata/device-root-bundle.pem", "")
	if err != nil {
		t.Fatalf("VerifySerializedEvidenceAllFile() error = %v", err)
	}
	if got, want := len(items), 4; got != want {
		t.Fatalf("len(items) = %d, want %d", got, want)
	}
	for i, item := range items {
		if !item.OK {
			t.Fatalf("item %d not OK: %+v", i, item)
		}
		if item.Result == nil {
			t.Fatalf("item %d result is nil", i)
		}
		if got, want := item.Result.InputFormat, "serialized-json"; got != want {
			t.Fatalf("item %d InputFormat = %q, want %q", i, got, want)
		}
	}
}

func TestVerifySampleQuoteWithOCSPAndRIM(t *testing.T) {
	opts := VerifyOptions{
		VerifyOCSP:    true,
		VerifyRIM:     true,
		DriverRIMPath: "../../testdata/NV_GPU_DRIVER_GH100_550.90.07.swidtag",
		VBIOSRIMPath:  "../../testdata/NV_GPU_VBIOS_1010_0200_882_96009F0001.swidtag",
		RIMRootPEM:    "../../testdata/verifier_RIM_root.pem",
		SWIDSchemaXSD: "../../testdata/swidSchema2015.xsd",
	}
	result, err := VerifyFilesWithOptions("../../testdata/hopperAttestationReport.txt", "../../testdata/hopperCertChain.txt", "../../testdata/device-root-bundle.pem", sampleNonce, opts)
	if err != nil {
		if strings.Contains(err.Error(), "certificate has expired") || strings.Contains(err.Error(), "is not yet valid") {
			t.Skipf("skipping time-sensitive OCSP/RIM sample test: %v", err)
		}
		t.Fatalf("VerifyFilesWithOptions() error = %v", err)
	}
	if result.DriverRIM == nil || !result.DriverRIM.SignatureVerified || !result.DriverRIM.CertChainVerified {
		t.Fatalf("unexpected driver rim result: %+v", result.DriverRIM)
	}
	if result.VBIOSRIM == nil || !result.VBIOSRIM.SignatureVerified || !result.VBIOSRIM.CertChainVerified {
		t.Fatalf("unexpected vbios rim result: %+v", result.VBIOSRIM)
	}
	if result.MeasurementVerification == nil || !result.MeasurementVerification.Verified {
		t.Fatalf("unexpected measurement verification: %+v", result.MeasurementVerification)
	}
	if len(result.DeviceOCSPChecks) == 0 {
		t.Fatal("expected device OCSP checks")
	}
}

func TestGenerateMockQuoteBundleVerifiesViaStandardPath(t *testing.T) {
	root, err := GenerateMockRootBundle(MockRootOptions{})
	if err != nil {
		t.Fatalf("GenerateMockRootBundle() error = %v", err)
	}
	bundle, err := GenerateMockQuoteBundleFromRoot(MockQuoteOptions{RootKey: root.RootKey, RootCert: root.RootCert})
	if err != nil {
		t.Fatalf("GenerateMockQuoteBundleFromRoot() error = %v", err)
	}
	dir := t.TempDir()
	quotePath := dir + "/quote.hex"
	chainPath := dir + "/cert-chain.pem"
	rootPath := dir + "/root.pem"
	if err := os.WriteFile(quotePath, bundle.QuoteHex, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chainPath, bundle.CertChainPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, bundle.RootCertPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := VerifyFilesWithOptions(quotePath, chainPath, rootPath, bundle.NonceHex, VerifyOptions{
		Policy: PolicyOptions{
			AllowedDriverVersions: []string{bundle.DriverVersion},
			AllowedVBIOSVersions:  []string{bundle.VBIOSVersion},
		},
	})
	if err != nil {
		t.Fatalf("VerifyFilesWithOptions(mock) error = %v", err)
	}
	if !result.CertChainVerified || !result.QuoteSignatureVerified || !result.NonceMatches || !result.FWIDMatches {
		t.Fatalf("unexpected mock result: %+v", result)
	}
	if got, want := result.DriverVersion, bundle.DriverVersion; got != want {
		t.Fatalf("DriverVersion = %q, want %q", got, want)
	}
	if got, want := result.VBIOSVersion, bundle.VBIOSVersion; got != want {
		t.Fatalf("VBIOSVersion = %q, want %q", got, want)
	}
	if result.PolicyVerification == nil || !result.PolicyVerification.Verified {
		t.Fatalf("expected policy verification to pass, got %+v", result.PolicyVerification)
	}
}

func TestMockSerializedEvidenceVerifiesViaStandardPath(t *testing.T) {
	root, err := GenerateMockRootBundle(MockRootOptions{})
	if err != nil {
		t.Fatalf("GenerateMockRootBundle() error = %v", err)
	}
	bundle, err := GenerateMockQuoteBundleFromRoot(MockQuoteOptions{RootKey: root.RootKey, RootCert: root.RootCert})
	if err != nil {
		t.Fatalf("GenerateMockQuoteBundleFromRoot() error = %v", err)
	}
	result, err := VerifySerializedEvidence(bundle.EvidenceJSON, bundle.RootCertPEM, 0, "")
	if err != nil {
		t.Fatalf("VerifySerializedEvidence(mock) error = %v", err)
	}
	if got, want := result.InputFormat, "serialized-json"; got != want {
		t.Fatalf("InputFormat = %q, want %q", got, want)
	}
	if got, want := result.EvidenceArch, "MOCK"; got != want {
		t.Fatalf("EvidenceArch = %q, want %q", got, want)
	}
	if !result.CertChainVerified || !result.QuoteSignatureVerified || !result.NonceMatches || !result.FWIDMatches {
		t.Fatalf("unexpected mock serialized result: %+v", result)
	}
}

func TestMockQuoteRequiresRootMaterial(t *testing.T) {
	if _, err := GenerateMockQuoteBundleFromRoot(MockQuoteOptions{}); err == nil {
		t.Fatal("GenerateMockQuoteBundleFromRoot() unexpectedly succeeded without root material")
	}
}
