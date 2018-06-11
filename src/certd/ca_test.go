package certd

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func Test_CA(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	_, err = SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	if _, err := LoadCA(tmpfile.Name()); err != nil {
		t.Error(err)
	}
}

func Test_CA_Setup_error(t *testing.T) {
	_, err := SetupCA("")
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func Test_CA_Setup_path_error(t *testing.T) {
	_, err := SetupCA("does/not/exist/config.json")
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func Test_CA_Load_error(t *testing.T) {
	if _, err := LoadCA(""); err == nil {
		t.Errorf("expected error, got nil")
	}
}

func Test_CA_Load_error_not_exist(t *testing.T) {
	if _, err := LoadCA("does not exist"); err == nil {
		t.Errorf("expected error, got nil")
	}
}

func Test_CA_Load_error_json(t *testing.T) {
	if _, err := LoadCA("ca.go"); err == nil {
		t.Errorf("expected error, got nil")
	}
}

func Test_CA_Load_error_read(t *testing.T) {
	if _, err := LoadCA("../certd"); err == nil {
		t.Errorf("expected error, got nil")
	}
}

func Test_CA_Cert_Key(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, err := SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	block, _ := pem.Decode(c.CertBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("failed to decode PEM block containing certificate")
	}
	if _, err = x509.ParseCertificates(block.Bytes); err != nil {
		t.Error(err)
	}

	block, _ = pem.Decode(c.KeyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Errorf("failed to decode PEM block containing private key")
	}
	if _, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Error(err)
	}
}

func Test_CA_Cert(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, err := SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	if _, err := c.Cert(); err != nil {
		t.Error(err)
	}
}

func Test_CA_Cert_error(t *testing.T) {
	c := CA{CertBytes: nil}
	if _, err := c.Cert(); err == nil {
		t.Errorf("expected an error")
	}
}

func Test_CA_Key(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, err := SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	if _, err := c.PrivateKey(); err != nil {
		t.Error(err)
	}
}

func Test_CA_Key_error(t *testing.T) {
	c := CA{KeyBytes: nil}
	if _, err := c.PrivateKey(); err == nil {
		t.Errorf("expected an error")
	}
}

func Test_CA_WriteCert(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, _ := SetupCA(tmpfile.Name())

	if err := c.WriteCert(tmpfile.Name()); err != nil {
		t.Error(err)
	}

}

func Test_CA_CertFromCSR(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, err := SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	csr, _ := CreateCSR("localhost,127.0.0.1")

	if _, err := c.CertFromCSR(csr); err != nil {
		t.Error(err)
	}
}

func Test_CA_CertFromCSR_fail_on_cert(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, err := SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	c.CertBytes = nil
	csr, _ := CreateCSR("localhost,127.0.0.1")

	if _, err := c.CertFromCSR(csr); err == nil {
		t.Errorf("expected an error")
	}
}

func Test_CA_CertFromCSR_fail_on_key(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, err := SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	c.KeyBytes = nil
	csr, _ := CreateCSR("localhost,127.0.0.1")

	if _, err := c.CertFromCSR(csr); err == nil {
		t.Errorf("expected an error")
	}
}

func Test_CA_genCert(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, err := SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	s := NewServer(c, "", "1234", "")
	handler := http.HandlerFunc(s.ServeHTTP)

	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/req?hosts=localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.SetBasicAuth(DefaultUser, DefaultPassword)

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("incorrect HTTP response code, expected %v got %v", http.StatusOK, rr.Code)
	}

}

func Test_CA_genCert_badauth(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, err := SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	s := NewServer(c, "", "1234", "")
	handler := http.HandlerFunc(s.ServeHTTP)

	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/req?hosts=localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.SetBasicAuth(DefaultUser, "wrongpassword")

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("incorrect HTTP response code, expected %v got %v", http.StatusUnauthorized, rr.Code)
	}

}

func Test_CA_genCert_noauth(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "certd")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	c, err := SetupCA(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	s := NewServer(c, "", "1234", "")
	handler := http.HandlerFunc(s.ServeHTTP)

	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/req?hosts=localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("incorrect HTTP response code, expected %v got %v", http.StatusUnauthorized, rr.Code)
	}

}
