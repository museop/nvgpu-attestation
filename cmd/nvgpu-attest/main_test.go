package main

import (
	"reflect"
	"testing"
)

func TestNormalizeLegacyLongFlags(t *testing.T) {
	got := normalizeLegacyLongFlags([]string{
		"verify",
		"-verify-ocsp",
		"-driver-rim=driver.swidtag",
		"--json",
		"-h",
		"value",
	})
	want := []string{
		"verify",
		"--verify-ocsp",
		"--driver-rim=driver.swidtag",
		"--json",
		"-h",
		"value",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeLegacyLongFlags() = %#v, want %#v", got, want)
	}
}

func TestParseVerificationTime(t *testing.T) {
	got, err := parseVerificationTime("2026-05-25T00:00:00Z")
	if err != nil {
		t.Fatalf("parseVerificationTime() error = %v", err)
	}
	if got.IsZero() || got.Format("2006-01-02T15:04:05Z07:00") != "2026-05-25T00:00:00Z" {
		t.Fatalf("unexpected parsed time: %s", got)
	}
	zero, err := parseVerificationTime("")
	if err != nil {
		t.Fatalf("parseVerificationTime(empty) error = %v", err)
	}
	if !zero.IsZero() {
		t.Fatalf("empty time should parse to zero, got %s", zero)
	}
	if _, err := parseVerificationTime("2026-05-25"); err == nil {
		t.Fatal("parseVerificationTime(invalid) unexpectedly succeeded")
	}
}
