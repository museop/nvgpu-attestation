package nvgpu

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

func compareMeasurements(quote *Quote, driverDoc, vbiosDoc *rimDocument, nvdecDisabled bool) (*MeasurementSummary, error) {
	runtime := quote.Response.getMeasurements()
	golden, err := activeGoldenMeasurements(driverDoc, vbiosDoc)
	if err != nil {
		return &MeasurementSummary{}, err
	}

	keys := make([]int, 0, len(golden))
	for k := range golden {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	summary := &MeasurementSummary{RuntimeCount: len(runtime), ActiveGoldenCount: len(golden)}
	for _, idx := range keys {
		if idx == 35 && nvdecDisabled {
			summary.SkippedMeasurement = append(summary.SkippedMeasurement, idx)
			continue
		}
		if idx < 0 || idx >= len(runtime) {
			summary.Mismatched = append(summary.Mismatched, MeasurementMismatch{Index: idx, Source: golden[idx].Source})
			continue
		}
		if !measurementMatches(golden[idx], runtime[idx]) {
			summary.Mismatched = append(summary.Mismatched, MeasurementMismatch{Index: idx, Source: golden[idx].Source})
		}
	}
	summary.Verified = len(summary.Mismatched) == 0
	if !summary.Verified {
		return summary, errors.New("runtime measurements do not match golden measurements")
	}
	return summary, nil
}

func activeGoldenMeasurements(driverDoc, vbiosDoc *rimDocument) (map[int]goldenMeasurement, error) {
	golden := map[int]goldenMeasurement{}
	for idx, gm := range driverDoc.Measurements {
		if gm.Active {
			golden[idx] = gm
		}
	}
	for idx, gm := range vbiosDoc.Measurements {
		if !gm.Active {
			continue
		}
		if _, exists := golden[idx]; exists {
			return nil, fmt.Errorf("driver and vbios rim share active measurement index %d", idx)
		}
		golden[idx] = gm
	}
	return golden, nil
}

func measurementMatches(gm goldenMeasurement, runtime string) bool {
	for _, alt := range gm.Alternatives {
		if strings.EqualFold(alt, runtime) && gm.Size*2 == len(runtime) {
			return true
		}
	}
	return false
}

func (r Response) getMeasurements() []string {
	record := r.MeasurementRecord
	count := int(r.MeasurementBlockCount)
	measurements := make([]string, count)
	for i := 0; i < len(record); {
		if len(record[i:]) < 4 {
			break
		}
		idx := int(record[i])
		i++
		_ = record[i]
		i++
		size := int(readLE(record[i : i+2]))
		i += 2
		if len(record[i:]) < size {
			break
		}
		block := record[i : i+size]
		i += size
		if len(block) < 3 || idx <= 0 || idx > count {
			continue
		}
		valSize := int(readLE(block[1:3]))
		if len(block) < 3+valSize {
			continue
		}
		measurements[idx-1] = hex.EncodeToString(block[3 : 3+valSize])
	}
	return measurements
}
