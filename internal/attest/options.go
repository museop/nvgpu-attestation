package attest

import "time"

const (
	DefaultOCSPURL       = "https://ocsp.ndis.nvidia.com"
	DefaultRIMServiceURL = "https://rim.attestation.nvidia.com/v1/rim/"
)

type RIMOptions struct {
	OCSPURL          string
	RIMServiceURL    string
	RIMRootPEM       string
	SWIDSchemaXSD    string
	SkipRIMOCSP      bool
	VerificationTime time.Time
}

type OCSPCheck struct {
	CertificateSubject string `json:"certificate_subject"`
	IssuerSubject      string `json:"issuer_subject"`
	Status             string `json:"status"`
	ThisUpdate         string `json:"this_update,omitempty"`
	NextUpdate         string `json:"next_update,omitempty"`
}

type RIMVerification struct {
	ID                string      `json:"id,omitempty"`
	Source            string      `json:"source"`
	Version           string      `json:"version,omitempty"`
	CertChainVerified bool        `json:"cert_chain_verified"`
	SignatureVerified bool        `json:"signature_verified"`
	SchemaValidated   bool        `json:"schema_validated"`
	OCSPChecks        []OCSPCheck `json:"ocsp_checks,omitempty"`
	MeasurementCount  int         `json:"measurement_count,omitempty"`
	FetchedSHA256     string      `json:"fetched_sha256,omitempty"`
}

type MeasurementMismatch struct {
	Index  int    `json:"index"`
	Source string `json:"source"`
}

type MeasurementSummary struct {
	Verified           bool                  `json:"verified"`
	RuntimeCount       int                   `json:"runtime_count"`
	ActiveGoldenCount  int                   `json:"active_golden_count"`
	Mismatched         []MeasurementMismatch `json:"mismatched,omitempty"`
	SkippedMeasurement []int                 `json:"skipped_measurements,omitempty"`
}
