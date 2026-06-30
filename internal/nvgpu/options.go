package nvgpu

import (
	"time"

	"github.com/museop/nvgpu-attestation/internal/attest"
)

const (
	defaultOCSPURL       = attest.DefaultOCSPURL
	defaultRIMServiceURL = attest.DefaultRIMServiceURL
)

type VerifyOptions struct {
	VerifyOCSP       bool
	VerifyRIM        bool
	OCSPURL          string
	RIMServiceURL    string
	DriverRIMPath    string
	VBIOSRIMPath     string
	RIMRootPEM       string
	SWIDSchemaXSD    string
	SkipRIMOCSP      bool
	VerificationTime time.Time
	Policy           PolicyOptions
}

type OCSPCheck = attest.OCSPCheck
type RIMVerification = attest.RIMVerification
type MeasurementMismatch = attest.MeasurementMismatch
type MeasurementSummary = attest.MeasurementSummary
