package attest

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type GoldenMeasurement struct {
	Index        int
	Source       string
	Active       bool
	Size         int
	Alternatives []string
}

func CompareMeasurements(runtime []string, golden map[int]GoldenMeasurement, skipIndexes map[int]bool, mismatchMessage string) (*MeasurementSummary, error) {
	keys := make([]int, 0, len(golden))
	for k := range golden {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	summary := &MeasurementSummary{RuntimeCount: len(runtime), ActiveGoldenCount: len(golden)}
	for _, idx := range keys {
		if skipIndexes[idx] {
			summary.SkippedMeasurement = append(summary.SkippedMeasurement, idx)
			continue
		}
		if idx < 0 || idx >= len(runtime) {
			summary.Mismatched = append(summary.Mismatched, MeasurementMismatch{Index: idx, Source: golden[idx].Source})
			continue
		}
		if !MeasurementMatches(golden[idx], runtime[idx]) {
			summary.Mismatched = append(summary.Mismatched, MeasurementMismatch{Index: idx, Source: golden[idx].Source})
		}
	}
	summary.Verified = len(summary.Mismatched) == 0
	if !summary.Verified {
		if mismatchMessage == "" {
			mismatchMessage = "runtime measurements do not match golden measurements"
		}
		return summary, errors.New(mismatchMessage)
	}
	return summary, nil
}

func ActiveGoldenMeasurements(docs ...*RIMDocument) (map[int]GoldenMeasurement, error) {
	golden := map[int]GoldenMeasurement{}
	for _, doc := range docs {
		if doc == nil {
			continue
		}
		for idx, gm := range doc.Measurements {
			if !gm.Active {
				continue
			}
			if _, exists := golden[idx]; exists {
				return nil, fmt.Errorf("rim documents share active measurement index %d", idx)
			}
			golden[idx] = gm
		}
	}
	return golden, nil
}

func MeasurementMatches(gm GoldenMeasurement, runtime string) bool {
	for _, alt := range gm.Alternatives {
		if strings.EqualFold(alt, runtime) && gm.Size*2 == len(runtime) {
			return true
		}
	}
	return false
}
