package nvgpu

import (
	"fmt"
	"os"
	"time"

	"github.com/museop/nvgpu-attestation/internal/attest"
)

func VerifyFiles(quotePath, certChainPath, rootsPath string, expectedNonceHex string) (*Result, error) {
	quoteData, err := os.ReadFile(quotePath)
	if err != nil {
		return nil, fmt.Errorf("read quote: %w", err)
	}
	chainData, err := os.ReadFile(certChainPath)
	if err != nil {
		return nil, fmt.Errorf("read cert chain: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("read roots: %w", err)
	}
	result, err := Verify(quoteData, chainData, rootsData, expectedNonceHex)
	if result != nil {
		result.InputFormat = "split-files"
	}
	return result, err
}

func VerifySerializedEvidenceFile(jsonPath, rootsPath string, index int, expectedNonceHex string) (*Result, error) {
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read serialized evidence: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("read roots: %w", err)
	}
	return VerifySerializedEvidence(jsonData, rootsData, index, expectedNonceHex)
}

func VerifySerializedEvidenceAllFile(jsonPath, rootsPath string, expectedNonceHex string) ([]BatchItem, error) {
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read serialized evidence: %w", err)
	}
	rootsData, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("read roots: %w", err)
	}
	return VerifySerializedEvidenceAll(jsonData, rootsData, expectedNonceHex)
}

func Verify(quoteInput, certChainPEM, rootsPEM []byte, expectedNonceHex string) (*Result, error) {
	result, _, _, err := verifyDetailed(quoteInput, certChainPEM, rootsPEM, expectedNonceHex, "", "", time.Time{})
	return result, err
}

func VerifySerializedEvidence(serializedJSON, rootsPEM []byte, index int, expectedNonceHex string) (*Result, error) {
	entries, err := attest.ParseSerializedEvidenceEntries(serializedJSON)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(entries) {
		return nil, fmt.Errorf("serialized evidence index out of range: got %d, valid range is 0..%d", index, len(entries)-1)
	}
	return verifySerializedEvidenceEntry(entries[index], rootsPEM, expectedNonceHex)
}

func VerifySerializedEvidenceAll(serializedJSON, rootsPEM []byte, expectedNonceHex string) ([]BatchItem, error) {
	entries, err := attest.ParseSerializedEvidenceEntries(serializedJSON)
	if err != nil {
		return nil, err
	}
	items := make([]BatchItem, 0, len(entries))
	for i, entry := range entries {
		result, verifyErr := verifySerializedEvidenceEntry(entry, rootsPEM, expectedNonceHex)
		item := BatchItem{
			Index:  i,
			Arch:   entry.Arch,
			OK:     verifyErr == nil,
			Result: result,
		}
		if verifyErr != nil {
			item.Error = verifyErr.Error()
		}
		items = append(items, item)
	}
	return items, nil
}

func verifySerializedEvidenceEntry(entry SerializedEvidenceEntry, rootsPEM []byte, expectedNonceHex string) (*Result, error) {
	result, _, _, err := verifySerializedEntryDetailed(entry, rootsPEM, expectedNonceHex, time.Time{})
	return result, err
}
