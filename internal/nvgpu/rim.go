package nvgpu

import (
	"strings"

	"github.com/museop/nvgpu-attestation/internal/attest"
)

func verifyRIMsAndMeasurements(result *Result, quote *Quote, opts VerifyOptions) (*MeasurementSummary, *RIMVerification, *RIMVerification, error) {
	driverID := "NV_GPU_DRIVER_GH100_" + result.DriverVersion
	vbiosID := strings.ToUpper("NV_GPU_VBIOS_" + attest.DecodeCString(quote.Response.OpaqueFields[17]) + "_" + attest.DecodeCString(quote.Response.OpaqueFields[18]) + "_" + attest.DecodeCString(quote.Response.OpaqueFields[15]) + "_" + strings.ReplaceAll(result.VBIOSVersion, ".", ""))

	driverDoc, driverInfo, err := attest.LoadAndVerifyRIM(driverID, "driver", result.DriverVersion, opts.DriverRIMPath, rimOptions(opts))
	if err != nil {
		return nil, driverInfo, nil, err
	}
	vbiosDoc, vbiosInfo, err := attest.LoadAndVerifyRIM(vbiosID, "vbios", result.VBIOSVersion, opts.VBIOSRIMPath, rimOptions(opts))
	if err != nil {
		return nil, driverInfo, vbiosInfo, err
	}
	summary, err := compareMeasurements(quote, driverDoc, vbiosDoc, result.NVDEC0Status == "disabled")
	if err != nil {
		return summary, driverInfo, vbiosInfo, err
	}
	return summary, driverInfo, vbiosInfo, nil
}

func rimOptions(opts VerifyOptions) attest.RIMOptions {
	return attest.RIMOptions{
		OCSPURL:          opts.OCSPURL,
		RIMServiceURL:    opts.RIMServiceURL,
		RIMRootPEM:       opts.RIMRootPEM,
		SWIDSchemaXSD:    opts.SWIDSchemaXSD,
		SkipRIMOCSP:      opts.SkipRIMOCSP,
		VerificationTime: opts.VerificationTime,
	}
}
