package commands

import (
	"testing"
)

func TestECgen(t *testing.T) {

	var (
		err error
	)

	Verbose = true
	inputPath = "testECpriv.pem"

	// Default P-256 behaviour
	err = genECDSA()
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	// Test saving pub key
	outputPath = "testECpub.pem"
	err = extractECDSAPub()
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}
}
