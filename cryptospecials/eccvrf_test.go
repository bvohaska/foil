package cryptospecials

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"testing"
)

/*
 * This test only test logical viability; crypto testing still required
 */
func TestEccVrf(t *testing.T) {

	var (
		valid   bool
		verbose bool
		alpha   []byte

		pubK   ECCPoint
		eccVrf ECCVRF
		err    error
	)

	verbose = true
	alpha = []byte("I am ecc VRF input")
	ec := elliptic.P256()

	pubK, eccVrf.EccProof, eccVrf.Beta, err = eccVrf.Generate(sha256.New(), ec, alpha, verbose)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}

	fmt.Println("********** Start Validation **********")
	valid, err = eccVrf.Verify(sha256.New(), &pubK, ec, alpha, eccVrf.Beta, &eccVrf.EccProof, verbose)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	if valid == false {
		t.Errorf("FAIL - Validity falure")
	}
	_ = pubK
	//t.Errorf("Test")
}
