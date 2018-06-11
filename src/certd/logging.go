package certd

import (
	"bytes"
	"log"
	"os"
)

func init() {
	// should only be used during testing
	if os.Getenv("RUNNING_TESTS") == "1" {
		b := make([]byte, 8192)
		buf := bytes.NewBuffer(b)
		log.SetOutput(buf)
	}
}
