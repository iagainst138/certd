package certd

import (
	"testing"
)

func Test_CreateCSR(t *testing.T) {
	if _, err := CreateCSR(""); err == nil {
		t.Errorf("excpected error creating CSR got %v", err)
	}
}
