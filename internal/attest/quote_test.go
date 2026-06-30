package attest

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const sampleNonceHex = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"

func TestDecodeHexOrRawAndParseQuoteSample(t *testing.T) {
	input, err := os.ReadFile("../../testdata/hopperAttestationReport.txt")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeHexOrRaw(input)
	if err != nil {
		t.Fatalf("DecodeHexOrRaw() error = %v", err)
	}
	quote, err := ParseQuote(raw)
	if err != nil {
		t.Fatalf("ParseQuote() error = %v", err)
	}
	expectedNonce, err := ParseNonce(sampleNonceHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(quote.Request.Nonce, expectedNonce) {
		t.Fatalf("request nonce = %x, want %x", quote.Request.Nonce, expectedNonce)
	}
	if got, want := quote.Response.MeasurementBlockCount, byte(64); got != want {
		t.Fatalf("MeasurementBlockCount = %d, want %d", got, want)
	}
	if got, want := len(quote.Response.Signature), SignatureLength; got != want {
		t.Fatalf("signature length = %d, want %d", got, want)
	}
	if got := len(quote.Response.GetMeasurements()); got != 64 {
		t.Fatalf("len(GetMeasurements()) = %d, want 64", got)
	}
}

func TestDecodeHexOrRawRejectsOddHex(t *testing.T) {
	_, err := DecodeHexOrRaw([]byte("abc"))
	if err == nil || !strings.Contains(err.Error(), "odd length") {
		t.Fatalf("DecodeHexOrRaw() error = %v, want odd length", err)
	}
}

func TestParseNonceValidation(t *testing.T) {
	if nonce, err := ParseNonce(sampleNonceHex); err != nil || len(nonce) != 32 {
		t.Fatalf("ParseNonce(valid) = len %d, err %v; want 32, nil", len(nonce), err)
	}
	if _, err := ParseNonce("00"); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("ParseNonce(short) error = %v, want 32-byte error", err)
	}
}

func TestParseSerializedEvidenceEntriesRejectsMissingFields(t *testing.T) {
	_, err := ParseSerializedEvidenceEntries([]byte(`[{"arch":"HOPPER","certificate":"","evidence":"abc","nonce":"00"}]`))
	if err == nil || !strings.Contains(err.Error(), "missing certificate") {
		t.Fatalf("ParseSerializedEvidenceEntries() error = %v, want missing certificate", err)
	}
}
