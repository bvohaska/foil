package cryptospecials

import (
	"crypto/ecdsa"
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

		privKey *ecdsa.PrivateKey
		pubK    ECCPoint
		eccVrf  ECCVRF
		err     error
	)

	verbose = true
	//verbose = false
	alpha = []byte("I am ecc VRF input")
	ec := elliptic.P256()

	// Loading the file and serializing is by far the most expoensive operation here
	privKey, err = EccPrivKeyLoad("ecPriv.pem")

	eccVrf.EccProof, eccVrf.Beta, err = eccVrf.Generate(sha256.New(), ec, privKey, alpha, verbose)
	if verbose {
		fmt.Println("EC-VRF Proof: ", eccVrf.EccProof)
	}
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}

	fmt.Println("********** Start Validation **********")
	valid, err = eccVrf.Verify(sha256.New(), &privKey.PublicKey, ec, alpha, eccVrf.Beta, &eccVrf.EccProof, verbose)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	if valid == false {
		t.Errorf("FAIL - Validity falure")
	}
	_ = pubK

	//fmt.Println(eccVrf.EccProof.x)
	//	t.Errorf("Test")
}
