package certd

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func Test_Server(t *testing.T) {
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
	s := NewServer(c, "127.0.0.1", "4443", "")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.ServeHTTP)

	endpoint := "/"

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func Test_Server_auth_setup(t *testing.T) {
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

	os.Setenv("CERTD_USER", "test")
	os.Setenv("CERTD_PASS", "test")

	defer func() {
		os.Setenv("CERTD_USER", "")
		os.Setenv("CERTD_PASS", "")
	}()

	s := NewServer(c, "127.0.0.1", "4443", "")
	if s.user != "test" {
		t.Errorf("user not set to env var")
	}
	if s.password != "test" {
		t.Errorf("password not set to env var")
	}
}

func Test_Listener_listenHTTPS(t *testing.T) {
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
	s := NewServer(c, "127.0.0.1", "4443", "")

	errChan := make(chan error)

	go func() {
		errChan <- s.Run()
	}()

	tick := time.Tick(2 * time.Second)
	select {
	case <-tick:
		return
	case e := <-errChan:
		t.Error(e)
	}
}

func Test_Server_dumpCA(t *testing.T) {
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
	s := NewServer(c, "127.0.0.1", "4443", "")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.ServeHTTP)

	req, err := http.NewRequest("GET", "/ca", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.SetBasicAuth(DefaultUser, DefaultPassword)

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func Test_Server_dumpCA_bad_auth(t *testing.T) {
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
	s := NewServer(c, "127.0.0.1", "4443", "")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.ServeHTTP)

	req, err := http.NewRequest("GET", "/ca", nil)
	if err != nil {
		t.Fatal(err)
	}

	//req.SetBasicAuth(DefaultUser, DefaultPassword)

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}

func Test_Server_no_req(t *testing.T) {
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
	s := NewServer(c, "127.0.0.1", "4443", "")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.ServeHTTP)

	req, err := http.NewRequest("GET", "/req", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.SetBasicAuth(DefaultUser, DefaultPassword)
	req.RemoteAddr = "127.0.0.1:1138"

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func Test_Server_plain(t *testing.T) {
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
	s := NewServer(c, "127.0.0.1", "4443", "")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.ServeHTTP)

	req, err := http.NewRequest("GET", "/req?output=plain", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.SetBasicAuth(DefaultUser, DefaultPassword)
	req.RemoteAddr = "127.0.0.1:1138"

	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	body := string(rr.Body.Bytes())
	if strings.Contains(body, "{") {
		t.Errorf("unexpected character in response")
	}
}

func Test_Server_404(t *testing.T) {
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
	s := NewServer(c, "127.0.0.1", "4443", "")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.ServeHTTP)

	endpoint := "/doesnotexist"

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNotFound)
	}
}
