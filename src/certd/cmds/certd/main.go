package main

import (
	"flag"
	"fmt"
	"os"

	"certd"
)

func main() {
	certAddrs := ""
	config := ""
	listen := "localhost"
	port := "4443"
	setup := false

	flag.BoolVar(&setup, "setup", setup, "setup a CA")
	flag.StringVar(&certAddrs, "cert-addrs", listen, "IPs and hostnames to generate certs for")
	flag.StringVar(&config, "config", config, "path to existing config")
	flag.StringVar(&listen, "listen", listen, "address to listen on")
	flag.StringVar(&port, "port", port, "port to listen on")
	flag.Parse()

	if _, err := os.Stat(config); os.IsNotExist(err) && setup {
		if _, err = certd.SetupCA(config); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	c, err := certd.LoadCA(config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s := certd.NewServer(c, listen, port, certAddrs)

	if err := s.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
