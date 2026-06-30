package nvswitch

import (
	"testing"
	"time"
)

const switchSampleNonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"

func TestVerifySwitchSampleReport(t *testing.T) {
	result, err := VerifyFilesWithOptions(
		"../../testdata/switchAttestationReport.txt",
		"../../testdata/switchCertChain.txt",
		"../../testdata/device-root-bundle.pem",
		switchSampleNonce,
		VerifyOptions{},
	)
	if err != nil {
		t.Fatalf("VerifyFilesWithOptions() error = %v", err)
	}
	if !result.CertChainVerified || !result.ReportSignatureVerified || !result.NonceMatches {
		t.Fatalf("unexpected result: %+v", result)
	}
	if got, want := result.SwitchBIOSVersion, "96.10.55.00.01"; got != want {
		t.Fatalf("SwitchBIOSVersion = %q, want %q", got, want)
	}
	if got, want := result.MeasurementBlockCount, 31; got != want {
		t.Fatalf("MeasurementBlockCount = %d, want %d", got, want)
	}
	if got, want := result.SwitchBIOSRIMID, "NV_SWITCH_BIOS_5612_0002_890_9610550001"; got != want {
		t.Fatalf("SwitchBIOSRIMID = %q, want %q", got, want)
	}
}

func TestVerifySwitchSerializedEvidenceSingle(t *testing.T) {
	result, err := VerifySerializedEvidenceFileWithOptions(
		"../../testdata/switch_evidence_ls10.json",
		"../../testdata/device-root-bundle.pem",
		0,
		"",
		VerifyOptions{},
	)
	if err != nil {
		t.Fatalf("VerifySerializedEvidenceFileWithOptions() error = %v", err)
	}
	if !result.CertChainVerified || !result.ReportSignatureVerified || !result.NonceMatches {
		t.Fatalf("unexpected result: %+v", result)
	}
	if got, want := result.EvidenceArch, "LS10"; got != want {
		t.Fatalf("EvidenceArch = %q, want %q", got, want)
	}
	if got, want := result.InputFormat, "serialized-json"; got != want {
		t.Fatalf("InputFormat = %q, want %q", got, want)
	}
}

func TestVerifySwitchSerializedEvidenceAll(t *testing.T) {
	items, err := VerifySerializedEvidenceAllFileWithOptions(
		"../../testdata/multi_switch_ls10.json",
		"../../testdata/device-root-bundle.pem",
		"",
		VerifyOptions{},
	)
	if err != nil {
		t.Fatalf("VerifySerializedEvidenceAllFileWithOptions() error = %v", err)
	}
	if got, want := len(items), 4; got != want {
		t.Fatalf("len(items) = %d, want %d", got, want)
	}
	for i, item := range items {
		if !item.OK {
			t.Fatalf("item %d not OK: %+v", i, item)
		}
		if item.Result == nil || !item.Result.ReportSignatureVerified {
			t.Fatalf("item %d missing verified result: %+v", i, item)
		}
	}
}

func TestVerifySwitchSampleReportWithLocalRIM(t *testing.T) {
	verificationTime, err := time.Parse(time.RFC3339, "2026-05-20T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyFilesWithOptions(
		"../../testdata/switchAttestationReport.txt",
		"../../testdata/switchCertChain.txt",
		"../../testdata/device-root-bundle.pem",
		switchSampleNonce,
		VerifyOptions{
			VerifyRIM:         true,
			SwitchBIOSRIMPath: "../../testdata/switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml",
			RIMRootPEM:        "../../testdata/verifier_RIM_root.pem",
			SWIDSchemaXSD:     "../../testdata/swidSchema2015.xsd",
			SkipRIMOCSP:       true,
			VerificationTime:  verificationTime,
		},
	)
	if err != nil {
		t.Fatalf("VerifyFilesWithOptions(RIM) error = %v", err)
	}
	if result.SwitchBIOSRIM == nil || !result.SwitchBIOSRIM.CertChainVerified || !result.SwitchBIOSRIM.SignatureVerified {
		t.Fatalf("unexpected switch BIOS RIM result: %+v", result.SwitchBIOSRIM)
	}
	if result.MeasurementVerification == nil || !result.MeasurementVerification.Verified {
		t.Fatalf("unexpected measurement verification: %+v", result.MeasurementVerification)
	}
}
