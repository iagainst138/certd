package certd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// CSR is a certificate signing request
type CSR struct {
	PrivateKey         []byte
	CertificateRequest *x509.CertificateRequest
	Hosts              string
}

// CreateCSR creates a certificate signing request for the given hosts/ips
func CreateCSR(hosts string) (*CSR, error) {
	if hosts == "" {
		return nil, fmt.Errorf("no hosts specified")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, RSABits)
	if err != nil {
		return nil, err
	}

	name := pkix.Name{
		Country:            []string{"IE"},
		Organization:       []string{"CERTD"},
		OrganizationalUnit: []string{"CERTD"},
		Locality:           []string{"Cork"},
		Province:           []string{"Cork"},
		SerialNumber:       string(time.Now().UnixNano()),
		CommonName:         strings.Split(hosts, ",")[0],
	}
	raw := name.ToRDNSequence()

	asn1Subj, _ := asn1.Marshal(raw)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	certReq, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certReq}
	pem.EncodeToMemory(pemBlock)

	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if err = clientCSR.CheckSignature(); err != nil {
		return nil, err
	}

	var keyOut bytes.Buffer
	pem.Encode(&keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	csr := &CSR{
		PrivateKey:         keyOut.Bytes(),
		CertificateRequest: clientCSR,
		Hosts:              hosts,
	}

	return csr, nil
}
