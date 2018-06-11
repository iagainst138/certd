package certd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

const (
	RSABits = 2048
	OneYear = 365 * 24 * time.Hour
)

// Cert holds a cert and private key
type Cert struct {
	CertBytes []byte `json:"cert,omitempty"`
	KeyBytes  []byte `json:"private_key,omitempty"`
}

func (c *Cert) String() string {
	return fmt.Sprintf("%v%v", string(c.CertBytes), string(c.KeyBytes))
}

// JSON returns a JSON encoded representation of the Cert
func (c *Cert) JSON() (string, error) {
	type out struct {
		Cert string `json:"cert"`
		Key  string `json:"private_key"`
	}
	o := out{string(c.CertBytes), string(c.KeyBytes)}
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *Cert) Plain() (string, error) {
	return fmt.Sprintf("%v\n%v", string(c.CertBytes), string(c.KeyBytes)), nil
}

// CA holds the cert and key for signing new certs
type CA struct {
	CertBytes []byte `json:"cert,omitempty"`
	KeyBytes  []byte `json:"private_key,omitempty"`
}

// LoadCA loads a CA from a JSON based config file
func LoadCA(path string) (*CA, error) {
	if path == "" {
		return nil, fmt.Errorf("no config specified")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("error: config \"%v\" does not exist", path)
	}

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	c := &CA{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}

	return c, nil
}

// SetupCA creates a new CA and stores its config at path
func SetupCA(path string) (*CA, error) {
	if path == "" {
		return nil, fmt.Errorf("no config specified")
	}

	c := &CA{}
	c.GenerateCert()

	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := ioutil.WriteFile(path, b, 0600); err != nil {
		return nil, err
	}

	return c, nil
}

// Cert returns an x509.Certificate based on the contents of CertBytes
func (c *CA) Cert() (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(c.CertBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("pem.Decode failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return caCRT, nil
}

// PrivateKey returns an rsa.PrivateKey based on the contents of KeyBytes
func (c *CA) PrivateKey() (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(c.KeyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("pem.Decode failed")
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return caPrivateKey, nil
}

// WriteCert writes the CA cert to disk
func (c *CA) WriteCert(path string) error {
	return ioutil.WriteFile(path, c.CertBytes, 0600)
}

// CertFromCSR creates a cert from a certificate request
func (c *CA) CertFromCSR(csr *CSR) (*Cert, error) {
	clientCSR := csr.CertificateRequest

	caPrivateKey, err := c.PrivateKey()
	if err != nil {
		return nil, err
	}

	caCRT, err := c.Cert()
	if err != nil {
		return nil, err
	}

	// create client certificate template
	template := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,

		NotBefore: time.Now(),
		NotAfter:  caCRT.NotAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,

		IsCA: false,
	}

	for _, h := range strings.Split(csr.Hosts, ",") {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &template, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw}); err != nil {
		return nil, err
	}

	cert := &Cert{
		CertBytes: buf.Bytes(),
		KeyBytes:  csr.PrivateKey,
	}

	return cert, nil
}

// GenerateCert creates the root CA
func (c *CA) GenerateCert() error {
	log.Println("generating new CA cert and key")
	privateKey, err := rsa.GenerateKey(rand.Reader, RSABits)
	if err != nil {
		return err
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(OneYear)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	log.Printf("using generated serial number %v", serialNumber)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "CERTD",

			Organization:       []string{"CERTD"},
			OrganizationalUnit: []string{"CERTD"},

			Country:  []string{"IE"},
			Province: []string{"Cork"},
			Locality: []string{"Cork"},
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		BasicConstraintsValid: true,

		IsCA: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	var certOut bytes.Buffer
	pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	var keyOut bytes.Buffer
	pem.Encode(&keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	c.CertBytes = certOut.Bytes()
	c.KeyBytes = keyOut.Bytes()

	log.Println("new CA cert and key generated successfully")
	return nil
}
