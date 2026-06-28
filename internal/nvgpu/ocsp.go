package nvgpu

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// checkOCSPChain checks adjacent certificate/issuer pairs. startIndex lets the
// device path skip the FMC leaf while the RIM path checks from its signer cert.
func checkOCSPChain(chain []*x509.Certificate, startIndex int, ocspURL string) ([]OCSPCheck, error) {
	if startIndex < 0 {
		startIndex = 0
	}
	if len(chain) < 2 || startIndex >= len(chain)-1 {
		return nil, nil
	}
	checks := make([]OCSPCheck, 0, len(chain)-1-startIndex)
	for i := startIndex; i < len(chain)-1; i++ {
		check, err := queryOCSP(chain[i], chain[i+1], ocspURL)
		checks = append(checks, check)
		if err != nil {
			return checks, err
		}
		if check.Status != "good" && check.Status != "revoked/certificateHold" {
			return checks, fmt.Errorf("ocsp status for %s is %s", check.CertificateSubject, check.Status)
		}
	}
	return checks, nil
}

func queryOCSP(cert, issuer *x509.Certificate, ocspURL string) (OCSPCheck, error) {
	check := OCSPCheck{CertificateSubject: cert.Subject.String(), IssuerSubject: issuer.Subject.String()}
	certFile, err := writeTempPEM(cert)
	if err != nil {
		return check, err
	}
	defer os.Remove(certFile)
	issuerFile, err := writeTempPEM(issuer)
	if err != nil {
		return check, err
	}
	defer os.Remove(issuerFile)

	cmd := exec.Command("openssl", "ocsp", "-issuer", issuerFile, "-cert", certFile, "-url", ocspURL, "-noverify", "-timeout", "10")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return check, fmt.Errorf("openssl ocsp failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return check, errors.New("empty OCSP response")
	}
	statusLine := strings.TrimSpace(lines[0])
	parts := strings.SplitN(statusLine, ":", 2)
	if len(parts) != 2 {
		return check, fmt.Errorf("unexpected OCSP output: %s", statusLine)
	}
	check.Status = strings.TrimSpace(parts[1])
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "This Update:") {
			check.ThisUpdate = strings.TrimSpace(strings.TrimPrefix(line, "This Update:"))
		}
		if strings.HasPrefix(line, "Next Update:") {
			check.NextUpdate = strings.TrimSpace(strings.TrimPrefix(line, "Next Update:"))
		}
		if strings.Contains(line, "certificateHold") {
			check.Status = "revoked/certificateHold"
		}
	}
	return check, nil
}
