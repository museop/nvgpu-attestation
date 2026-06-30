package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

var (
	reSignatureOpen  = regexp.MustCompile(`<([A-Za-z0-9_]+:)?Signature\b[\s\S]*?</([A-Za-z0-9_]+:)?Signature>`)
	reSignedInfo     = regexp.MustCompile(`<([A-Za-z0-9_]+:)?SignedInfo\b[\s\S]*?</([A-Za-z0-9_]+:)?SignedInfo>`)
	reSignedInfoOpen = regexp.MustCompile(`<([A-Za-z0-9_]+:)?SignedInfo\b`)
	reRootOpen       = regexp.MustCompile(`<SoftwareIdentity\b([^>]*)>`)
	reSigStart       = regexp.MustCompile(`<([A-Za-z0-9_]+:)?Signature\b([^>]*)>`)
	reXMLNS          = regexp.MustCompile(`xmlns(?::[A-Za-z0-9_]+)?="[^"]+"`)
)

func verifyRIMSignature(doc *RIMDocument) error {
	withoutSig := reSignatureOpen.ReplaceAll(doc.Raw, nil)
	c14nDocument, err := canonicalizeXML(withoutSig)
	if err != nil {
		return err
	}
	expectedDigest, err := base64.StdEncoding.DecodeString(doc.DigestValueBase64)
	if err != nil {
		return fmt.Errorf("decode rim digest: %w", err)
	}
	digest := sha512.Sum384(c14nDocument)
	if !bytes.Equal(digest[:], expectedDigest) {
		return errors.New("rim digest mismatch")
	}

	signedInfo := reSignedInfo.Find(doc.Raw)
	if len(signedInfo) == 0 {
		return errors.New("signedinfo element not found")
	}
	xmlnsDecls := collectXMLNSDecls(doc.Raw)
	if len(xmlnsDecls) > 0 {
		decls := " " + strings.Join(xmlnsDecls, " ")
		signedInfo = reSignedInfoOpen.ReplaceAll(signedInfo, []byte(`${0}`+decls))
	}
	c14nSignedInfo, err := canonicalizeXML(signedInfo)
	if err != nil {
		return err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(doc.SignatureValueB64)
	if err != nil {
		return fmt.Errorf("decode rim signature value: %w", err)
	}
	pub, ok := doc.Certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported rim public key type %T", doc.Certs[0].PublicKey)
	}
	if len(sigBytes)%2 != 0 {
		return errors.New("unexpected rim ecdsa signature length")
	}
	hash := sha512.Sum384(c14nSignedInfo)
	r := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
	s := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("rim ecdsa signature invalid")
	}
	return nil
}

func collectXMLNSDecls(data []byte) []string {
	var rawDecls string
	if m := reRootOpen.FindSubmatch(data); len(m) == 2 {
		rawDecls += " " + string(m[1])
	}
	if m := reSigStart.FindSubmatch(data); len(m) == 3 {
		rawDecls += " " + string(m[2])
	}
	matches := reXMLNS.FindAllString(rawDecls, -1)
	seen := map[string]bool{}
	decls := make([]string, 0, len(matches))
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			decls = append(decls, m)
		}
	}
	sort.Strings(decls)
	return decls
}

func canonicalizeXML(data []byte) ([]byte, error) {
	tmp, err := writeTempBytes(data, ".xml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	cmd := exec.Command("xmllint", "--c14n11", tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("xmllint c14n11 failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
