package certd

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	DefaultUser     = "admin"
	DefaultPassword = "password"
)

// Server is what used to serve API requests for new certs
type Server struct {
	CA         *CA
	CertAddrs  string
	HTTPSPort  string
	ListenAddr string
	user       string
	password   string
}

// NewServer creates a new Server
func NewServer(ca *CA, listenAddr, port, certAddrs string) *Server {
	s := Server{
		CA:         ca,
		CertAddrs:  certAddrs,
		HTTPSPort:  port,
		ListenAddr: listenAddr,
		user:       DefaultUser,
		password:   DefaultPassword,
	}

	if u := os.Getenv("CERTD_USER"); u != "" {
		s.user = u
	}
	if p := os.Getenv("CERTD_PASS"); p != "" {
		s.password = p
	}
	return &s
}

// ServeHTTP reoutes requests
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "private, max-age=0")
	w.Header().Set("Expires", "0")

	log.Printf("%v - %v", req.RemoteAddr, req.URL.Path)

	switch req.URL.Path {
	case "/":
		w.Write([]byte(IndexPage))
	case "/req":
		s.genCert(w, req)
	case "/ca":
		s.dumpCA(w, req)
	default:
		http.NotFound(w, req)
	}
}

func (s *Server) dumpCA(w http.ResponseWriter, req *http.Request) {
	if !s.Authorized(w, req) {
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "inline; filename=ca.crt")
	w.Write(s.CA.CertBytes)
}

func (s *Server) genCert(w http.ResponseWriter, req *http.Request) {
	if !s.Authorized(w, req) {
		return
	}

	if err := req.ParseForm(); err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	hosts := req.FormValue("hosts")
	if hosts == "" {
		remoteAddr, _, _ := net.SplitHostPort(req.RemoteAddr)
		if hostAddrs, err := net.LookupIP(remoteAddr); err == nil {
			for _, h := range hostAddrs {
				hosts = fmt.Sprintf("%v,%v", h, hosts)
			}
		}
		hosts = strings.TrimRight(hosts, ",")
	}
	log.Printf("generating cert for \"%v\"", hosts)

	csr, err := CreateCSR(hosts)
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	cert, err := s.CA.CertFromCSR(csr)
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	output := ""
	fileName := ""
	outputType := req.FormValue("output")
	if outputType == "plain" {
		fileName = "cert.txt"
		output, _ = cert.Plain()
	} else {
		fileName = "cert.json"
		output, err = cert.JSON()
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "inline; filename=\""+fileName+"\"")
	fmt.Fprintf(w, "%v\n", output)
}

func (s *Server) listenHTTPS() error {
	addrs := s.CertAddrs
	if addrs == "" {
		addrs = s.ListenAddr
	}

	log.Printf("generating cert for: %v", addrs)
	csr, err := CreateCSR(addrs)
	if err != nil {
		return err
	}

	c, err := s.CA.CertFromCSR(csr)
	if err != nil {
		return err
	}
	certBytes, keyBytes := c.CertBytes, c.KeyBytes

	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", net.JoinHostPort(s.ListenAddr, s.HTTPSPort), config)
	if err != nil {
		return err
	}

	srv := http.Server{
		Handler: s,
	}

	log.Printf("listening for HTTPS connections on %v:%v", s.ListenAddr, s.HTTPSPort)
	return srv.Serve(listener)
}

// Authorized determines if the request is authorized
func (s *Server) Authorized(w http.ResponseWriter, req *http.Request) bool {
	if user, password, ok := req.BasicAuth(); ok {
		if (user == s.user) && (password == s.password) {
			return true
		} else {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"depot\"")
			w.WriteHeader(http.StatusUnauthorized)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return false
		}
	} else {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"certd\"")
		w.WriteHeader(http.StatusUnauthorized)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return false
	}
	return false
}

// Run starts the Server
func (s *Server) Run() error {
	return s.listenHTTPS()
}

var IndexPage = `<html>
<head>
<title>CertD</title>
<meta name="viewport" content="width=device-width, minimumscale=1.0, maximum-scale=1.0 user-scalable=no" />
<style type="text/css">
body {
	line-height: 1.6;
	font-size: 18px;
	color: #444;
	background: #ebebeb;
	padding: 0 10px;
	font-family: sans-serif;
}
h1,h2,h3 {
	line-height:1.2;
}
div, input {
	-moz-box-sizing: border-box;
	-webkit-box-sizing: border-box;
	box-sizing: border-box;
}

form label {
	font-family: inherit;
	display: block;
	width: 100%;
}

form input {
	font-family: inherit;
	padding: 4px;
}

form input[type="text"] {
	padding: 2px;
	padding-left: 4px;
	padding-right: 4px;
	height: 30px;
	width: 500px;
	border: 1px solid lightgray;
	border-radius: 2px;
}

input[type="submit"] {
	width: 75px;
	border-radius: 2px;
	background: linear-gradient(whitesmoke, white);
	border: 1px solid lightgray;
	color: inherit;
}

input[type="submit"]:hover {
	background: linear-gradient(white, whitesmoke);
	cursor: pointer;
}

.content {
	margin: 40px auto;
	max-width: 750px;
	padding: 10px 30px;
	border-radius: 2px;
	background: #fff;
	min-height: 800px;
}
.page_heading {
	border-bottom: 1px solid lightgray;
}

@media only screen and (max-width: 600px) {
body {
	background: white;
}

.content {
	margin: 0px;
	width: 100%;
	max-width: none;
	min-height: none;
	border-radius: 0px;
	padding: 4px;
}

form input[type="text"] {
	width: 100%;
}

}

</style>
</head>
<body>
<div class="content">
<h1 class="page_heading">CertD</h1>
<h4>Generate a cert</h4>
<form action="/req">
<label for="fname" title="A comma separated list of hostnames and/or IPs you wish to generate a cert for.">Hosts:</label>
    <input type="text" id="hosts" name="hosts" required autocomplete="off" placeholder="Comma separated list of hostnames and/or IPs">

    <p><input type="submit" value="Submit"></p>
</form>


<h4>CA Cert</h4>
<p>The root CA can be downloaded <a href="/ca">here</a>.</p>

<h4>API Usage</h4>
<p>Request certs from this CA by making a GET request to <i>/req</i>. By default a cert will be generated for the requesting host.</p>
<p>Use the option "hosts" for a different host.</p>
<p>Example: <i>/req?hosts=192.168.1.138,some-host.local</i></p>

</div>

</body>
</html>

`
