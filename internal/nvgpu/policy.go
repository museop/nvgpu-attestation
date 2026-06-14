package nvgpu

import "strings"

type PolicyOptions struct {
	AllowedDriverVersions          []string
	AllowedVBIOSVersions           []string
	AllowedArchitectures           []string
	RequireMeasurementVerification bool
	RequireDeviceOCSP              bool
}

type PolicyCheck struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

type PolicyResult struct {
	Verified bool          `json:"verified"`
	Checks   []PolicyCheck `json:"checks"`
}

func (o PolicyOptions) Enabled() bool {
	return len(o.AllowedDriverVersions) > 0 ||
		len(o.AllowedVBIOSVersions) > 0 ||
		len(o.AllowedArchitectures) > 0 ||
		o.RequireMeasurementVerification ||
		o.RequireDeviceOCSP
}

func AppraisePolicy(result *Result, opts PolicyOptions) *PolicyResult {
	policy := &PolicyResult{Verified: true}
	if result == nil {
		return &PolicyResult{Verified: false, Checks: []PolicyCheck{{Name: "result-present", OK: false}}}
	}
	if len(opts.AllowedDriverVersions) > 0 {
		policy.add("driver-version-allowed", containsFold(opts.AllowedDriverVersions, result.DriverVersion), strings.Join(opts.AllowedDriverVersions, ","), result.DriverVersion)
	}
	if len(opts.AllowedVBIOSVersions) > 0 {
		policy.add("vbios-version-allowed", containsFold(opts.AllowedVBIOSVersions, result.VBIOSVersion), strings.Join(opts.AllowedVBIOSVersions, ","), result.VBIOSVersion)
	}
	if len(opts.AllowedArchitectures) > 0 {
		policy.add("architecture-allowed", containsFold(opts.AllowedArchitectures, result.EvidenceArch), strings.Join(opts.AllowedArchitectures, ","), result.EvidenceArch)
	}
	if opts.RequireMeasurementVerification {
		ok := result.MeasurementVerification != nil && result.MeasurementVerification.Verified
		actual := "missing"
		if result.MeasurementVerification != nil {
			actual = boolString(result.MeasurementVerification.Verified)
		}
		policy.add("measurement-verification-required", ok, "true", actual)
	}
	if opts.RequireDeviceOCSP {
		ok := len(result.DeviceOCSPChecks) > 0
		actual := "missing"
		if len(result.DeviceOCSPChecks) > 0 {
			statuses := make([]string, 0, len(result.DeviceOCSPChecks))
			for _, check := range result.DeviceOCSPChecks {
				statuses = append(statuses, check.Status)
				ok = ok && strings.EqualFold(check.Status, "good")
			}
			actual = strings.Join(statuses, ",")
		}
		policy.add("device-ocsp-good-required", ok, "all good", actual)
	}
	return policy
}

func (p *PolicyResult) add(name string, ok bool, expected, actual string) {
	p.Checks = append(p.Checks, PolicyCheck{Name: name, OK: ok, Expected: expected, Actual: actual})
	p.Verified = p.Verified && ok
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
