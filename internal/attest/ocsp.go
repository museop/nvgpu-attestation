package attest

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func CheckOCSPChain(chain []*x509.Certificate, startIndex int, ocspURL string) ([]OCSPCheck, error) {
	var checks []OCSPCheck
	if len(chain) < 2 {
		return checks, nil
	}
	for i := startIndex; i < len(chain)-1; i++ {
		check, err := QueryOCSP(chain[i], chain[i+1], ocspURL)
		checks = append(checks, check)
		if err != nil {
			return checks, err
		}
		if check.Status != "good" {
			return checks, fmt.Errorf("ocsp status for %s is %s", check.CertificateSubject, check.Status)
		}
	}
	return checks, nil
}

func QueryOCSP(cert, issuer *x509.Certificate, ocspURL string) (OCSPCheck, error) {
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

	cmd := exec.Command("openssl", "ocsp", "-issuer", issuerFile, "-cert", certFile, "-url", ocspURL, "-noverify")
	out, err := cmd.CombinedOutput()
	text := string(out)
	check.Status = parseOCSPStatus(text)
	check.ThisUpdate = parseOCSPLine(text, "This Update:")
	check.NextUpdate = parseOCSPLine(text, "Next Update:")
	if err != nil && check.Status == "" {
		return check, fmt.Errorf("openssl ocsp failed: %w: %s", err, strings.TrimSpace(text))
	}
	if check.Status == "" {
		return check, errors.New("could not parse ocsp status")
	}
	return check, nil
}

func parseOCSPStatus(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, ": good"):
			return "good"
		case strings.Contains(lower, ": revoked"):
			return "revoked"
		case strings.Contains(lower, ": unknown"):
			return "unknown"
		case strings.Contains(lower, "certificatehold"):
			return "certificateHold"
		}
	}
	return ""
}

func parseOCSPLine(output, prefix string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}
