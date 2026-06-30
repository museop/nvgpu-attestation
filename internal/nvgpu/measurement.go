package nvgpu

import (
	"github.com/museop/nvgpu-attestation/internal/attest"
)

func compareMeasurements(quote *Quote, driverDoc, vbiosDoc *attest.RIMDocument, nvdecDisabled bool) (*MeasurementSummary, error) {
	golden, err := activeGoldenMeasurements(driverDoc, vbiosDoc)
	if err != nil {
		return &MeasurementSummary{}, err
	}
	skip := map[int]bool{}
	if nvdecDisabled {
		skip[35] = true
	}
	return attest.CompareMeasurements(quote.Response.GetMeasurements(), golden, skip, "runtime measurements do not match golden measurements")
}

func activeGoldenMeasurements(driverDoc, vbiosDoc *attest.RIMDocument) (map[int]attest.GoldenMeasurement, error) {
	return attest.ActiveGoldenMeasurements(driverDoc, vbiosDoc)
}
