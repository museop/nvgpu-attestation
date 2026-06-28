package nvgpu

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
)

func writeTempPEM(cert *x509.Certificate) (string, error) {
	return writeTempBytes(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), ".pem")
}

func writeTempBytes(data []byte, suffix string) (string, error) {
	f, err := os.CreateTemp("", "nvgpu-*"+suffix)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return filepath.Clean(f.Name()), nil
}
