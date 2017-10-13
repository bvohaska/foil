package commands

import (
	"encoding/hex"
	"fmt"
	"foil/cryptospecials"
	"os"
	"testing"
)

/*
	// Foil variables
	Verbose        bool
	stdOutBool     bool
	inputPath      string
	keyString      string
	outputPath     string
	passwordString string
	stdInString    string

	// VRF specific variables
	typeRSA     bool
	typeECC     bool
	typePriv    bool
	typePub     bool
	alphaString string
	betaString  string
	proofString string
	alpha       []byte
*/

func rsaFileCheck() error {

	var (
		err        error
		privString string
		pubString  string
	)

	privString = "testPrivKey.pem"
	pubString = "testPubKey.pem"

	_, err = os.Stat(privString)
	if !os.IsNotExist(err) {
		privKey, err := cryptospecials.RSAKeyGen(2048)
		if err != nil {
			return fmt.Errorf("FAIL - %v", err)
		}
		err = cryptospecials.RSAKeySave(privKey, false, false, &privString, false)
		if err != nil {
			return fmt.Errorf("FAIL - %v", err)
		}
		err = cryptospecials.RSAKeySave(privKey, true, false, &pubString, false)
		if err != nil {
			return fmt.Errorf("FAIL - %v", err)
		}
	}

	return nil
}

/*
*  In the absence of test vectors, these test functions test the correctness of
*  the functions and not necessarily the security. Vetting of these functions is
*  required.
 */
func TestVrfGenVer(t *testing.T) {

	var (
		validity bool
		proof    []byte
		beta     []byte
		err      error
	)

	Verbose = false
	pathPriv = "testPrivKey.pem"
	pathPub = "testPubKey.pem"

	alphaString = "LegitString"
	proofString = "b054a99aed22af4fe5d43c1e76883f2120da7fe9e3be25e7ffbfcb7b51d067df" +
		"5e95c97b7e0b8f90b1826f45ac8718bd15815954aa264314beef47e2c0cc11c99ed0d9b180be094" +
		"8d81b0ef9f9f15536caf1ce8d3088726c961f084fc465e392a8b6eca872a270fb01a063384a56a1" +
		"3132ddc82acd1ba9b9b119661fc34ea015de8277f98b7d6c5ba516af9f30213a627d8b2367e4d8b" +
		"88aa18d830802ba1c986c35dc14d09cbb6592e4649a90fe30a5b8fb5c9b8388bf6a2d5c93c3daa8" +
		"c50e6a4431b580a3db74a2b1fbe57443da22013ce6f59ba0cdd4bf69cc8c8b53c05e50cc083042e" +
		"8a2736ba01193ec0b7e9df5c66329f42f77ac3ddd309a28c970a0"
	betaString = "47345fb1df669c4e4a147aa3c15ca0e9253cf00eecd1ec16107310bdb6d2205a"

	proof, beta, err = genRsaVrf()
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	if hex.EncodeToString(proof) != proofString {
		t.Errorf("FAIL - Proof generation failure")
	}
	if hex.EncodeToString(beta) != betaString {
		t.Errorf("FAIL - Beta generation failure")
	}

	validity, err = verRsaVrf()
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	if !validity {
		t.Errorf("FAIL - VRF verification failed.")
	}
}

func TestVrfGen(t *testing.T) {

}

func TestVrfVer(t *testing.T) {

}
