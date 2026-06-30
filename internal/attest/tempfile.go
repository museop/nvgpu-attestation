package attest

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
	file, err := os.CreateTemp("", "nvgpu-attest-*"+suffix)
	if err != nil {
		return "", err
	}
	path := file.Name()
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return filepath.Clean(path), nil
}
