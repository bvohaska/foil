package cryptospecials

import (
	"testing"
)

/*
*  This test does not garantee the cryptogrpahic viability of rsaVRF.generate() or rsaVRF.verfiy()
*  instead it checks the consistancy of generate and verfiy to validate the logic of EACH OTHER.
*  Further testing and validation of the cryptography is required.
 */
func TestRSAVRFGenVerify(t *testing.T) {

	var (
		verifyCheck bool
		verbose     bool
		alpha       []byte
		//mgf1Alpha   []byte
		err        error
		rsaVrfTest RSAVRF
	)

	// If set to true, most of the RSA and hashing parameters will be displayed
	verbose = false

	alpha = []byte("This is a test!")
	//mgf1Alpha = make([]byte, 255)
	//mgf1XOR(mgf1Alpha, sha256.New(), alpha)
	rsaVrfTest.Alpha = alpha

	// Expensive operation but allows for random testing which is critically important
	rsaVrfTest.PrivateKey, err = RSAKeyGen(2048)
	if err != nil {
		t.Errorf("FAIL - Error in RSAKeyGen(2048)")
	}

	rsaVrfTest.Proof, rsaVrfTest.Beta, err = rsaVrfTest.Generate(rsaVrfTest.Alpha, rsaVrfTest.PrivateKey, verbose)
	if err != nil {
		t.Errorf("Internal Error: %v\n", err)
	}
	verifyCheck, err = rsaVrfTest.Verify(rsaVrfTest.Alpha, rsaVrfTest.Beta, rsaVrfTest.Proof, &rsaVrfTest.PublicKey, verbose)
	if err != nil {
		t.Errorf("Internal Error: %v\n", err)
	}
	if verifyCheck == false {
		t.Errorf("FAIL - VRF verification failed")
	}
}
