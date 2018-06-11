package certd

import (
	"testing"
)

func Test_Cert_String(t *testing.T) {
	c := Cert{
		CertBytes: make([]byte, 0),
		KeyBytes:  make([]byte, 0),
	}

	if s := c.String(); len(s) != 0 {
		t.Errorf("cert.String failed: %v", s)
	}
}

func Test_Cert_JSON(t *testing.T) {
	c := Cert{
		CertBytes: make([]byte, 0),
		KeyBytes:  make([]byte, 0),
	}

	if _, err := c.JSON(); err != nil {
		t.Errorf("cert.JSON failed: %v", err)
	}
}

func Test_Cert_Plain(t *testing.T) {
	c := Cert{
		CertBytes: make([]byte, 0),
		KeyBytes:  make([]byte, 0),
	}

	if s, err := c.Plain(); err != nil {
		t.Errorf("cert.String failed: %v", err)
	} else if len(s) != 1 {
		t.Errorf("cert.String failed: %v", s)
	}
}
