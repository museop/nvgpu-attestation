package main

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeLegacyLongFlags(t *testing.T) {
	got := normalizeLegacyLongFlags([]string{
		"verify",
		"-verify-rim",
		"-switch-bios-rim=switch.xml",
		"--json",
		"-h",
		"value",
	})
	want := []string{
		"verify",
		"--verify-rim",
		"--switch-bios-rim=switch.xml",
		"--json",
		"-h",
		"value",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeLegacyLongFlags() = %#v, want %#v", got, want)
	}
}

func TestParseVerificationTime(t *testing.T) {
	got, err := parseVerificationTime("2026-05-20T00:00:00Z")
	if err != nil {
		t.Fatalf("parseVerificationTime() error = %v", err)
	}
	if got.IsZero() || got.Format("2006-01-02T15:04:05Z07:00") != "2026-05-20T00:00:00Z" {
		t.Fatalf("unexpected parsed time: %s", got)
	}
	zero, err := parseVerificationTime("")
	if err != nil {
		t.Fatalf("parseVerificationTime(empty) error = %v", err)
	}
	if !zero.IsZero() {
		t.Fatalf("empty time should parse to zero, got %s", zero)
	}
	if _, err := parseVerificationTime("2026-05-20"); err == nil {
		t.Fatal("parseVerificationTime(invalid) unexpectedly succeeded")
	}
}

func TestVerifyPlainTextOutputPreservesLabels(t *testing.T) {
	cmd := exec.Command("go", "run", "./cmd/nvswitch-attest", "verify")
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run ./cmd/nvswitch-attest verify error = %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{"verification OK", "cert chain verified", "report signature"} {
		if !strings.Contains(text, want) {
			t.Fatalf("plain text output missing %q:\n%s", want, text)
		}
	}
}
