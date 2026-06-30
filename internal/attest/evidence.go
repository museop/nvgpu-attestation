package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type SerializedEvidenceEntry struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
	Nonce       string `json:"nonce"`
}

func ParseSerializedEvidenceEntries(data []byte) ([]SerializedEvidenceEntry, error) {
	var entries []SerializedEvidenceEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse serialized evidence json: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("serialized evidence json is empty")
	}
	for i, entry := range entries {
		if strings.TrimSpace(entry.Evidence) == "" {
			return nil, fmt.Errorf("serialized evidence entry %d is missing evidence", i)
		}
		if strings.TrimSpace(entry.Certificate) == "" {
			return nil, fmt.Errorf("serialized evidence entry %d is missing certificate", i)
		}
		if strings.TrimSpace(entry.Nonce) == "" {
			return nil, fmt.Errorf("serialized evidence entry %d is missing nonce", i)
		}
	}
	return entries, nil
}
