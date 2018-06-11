package main

import (
	"flag"
	"fmt"
	"os"

	"certd"
)

func fail(err error) {
	fmt.Printf("error: %v\n", err)
	os.Exit(1)
}

func main() {
	config := ""
	outputJSON := false
	request := ""
	setup := false

	flag.BoolVar(&outputJSON, "json", outputJSON, "output request in json")
	flag.BoolVar(&setup, "setup", setup, "setup a CA")
	flag.StringVar(&config, "config", config, "path to config")
	flag.StringVar(&request, "request", request, "comma seperated list of IPs/hostnames")
	flag.Parse()

	c := &certd.CA{}
	var err error

	if config == "" {
		fmt.Println("error: no config specified\nusage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if setup {
		if c, err = certd.SetupCA(config); err != nil {
			fail(err)
		}
		fmt.Printf("config successfully written to \"%v\"\n", config)
	} else {
		if c, err = certd.LoadCA(config); err != nil {
			fail(err)
		}
	}

	if request != "" {
		clientCSR, err := certd.CreateCSR(request)
		if err != nil {
			fail(err)
		}

		cert, err := c.CertFromCSR(clientCSR)
		if err != nil {
			fail(err)
		}
		if outputJSON {
			if j, err := cert.JSON(); err == nil {
				fmt.Println(j)
			} else {
				fail(err)
			}
		} else {
			fmt.Println(cert)
		}
	} else if !setup {
		fmt.Printf("nothing to do\n\n")
		flag.PrintDefaults()
	}
}
