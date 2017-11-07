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

// Check to make sure the required PEM files are in the current testing directory
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
func TestRsaVrfGenVer(t *testing.T) {

	var (
		validity bool
		proof    []byte
		beta     []byte
		err      error
	)

	Verbose = true

	/*
	*  NOTE: These values are for proofString and betaString generated with a
	*  SPECIFIC pem. Change proofString and betaString if using another.
	*
	* 	These variables are global to Commands package
	 */
	alphaString = "LegitString"
	proofString = "8506a33f87e68efb8dc490cf3ad89ef1ba8465085afe89024708ed9c42a95c4" +
		"64682727a4f956323146e6a2cfc42935fb42e1e51c11121c5cadb1c1a6fb76" +
		"3dd0757ba6eaef5808451933da5bba4928a94c80f1776197f40622f795eaf0" +
		"c2772cbf69d5d17748642e92068dd7406800efe885e63aea08f4e8d5777a10" +
		"c7f5c35357ba80bc455fc6f1c482462905ae557c7fa59e0e28da20ccbf7122" +
		"20215662e19d09b8af16d1cdc2c259989c2997893b40e888b8c6c6c22ce58f" +
		"d7ed0635ee1d5d587fd78c1b75dff20916e637f63bf8da11a5fb2d1aad7766" +
		"ccd3077f4170111aacbf5fdd1f27059294e66cf77ce7ef88306ea00f0b1c94" +
		"4abacbbb2eee0e1"
	betaString = "5feabe59598852cce72ef186261196378bacc571975f8d26e6f91106cae2e02b"

	// genRsa takes in alphaString, pathPriv, Verbose
	inputPath = "testPrivKey.pem"
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

	inputPath = "testPubKey.pem"
	validity, err = verRsaVrf()
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	if !validity {
		t.Errorf("FAIL - VRF verification failed.")
	}
}

func TestECCVrfGenVer(t *testing.T) {

	var (
		valid  bool
		err    error
		eccVrf *cryptospecials.ECCVRF
	)

	eccVrf = new(cryptospecials.ECCVRF)
	Verbose = true
	//Verbose = false
	alphaString = "LegitString"

	// ProofString will change as k changes
	/*proofString = "bcccb418f210cb3e9942b3b8ef7cb177bae3a63b38318706c99c672380ef51f9" +
		", 4f1cf2628dc0b25ecbcb50520464f2b77a3c63c14c317113985bf6f765cf306d" +
		", 134a343ec74913a4e78df2d603adc810de1720c7b581bda56d718fd9ff541370" +
		", a51c43578982d71011cbcd1a8f0aee5ad1b917129c7d5748cb5dda63c1e3505d"
	betaString = "3cda8d5a1f5bd9078b52124356520e52a90beeab2bde290da9cab1ff41c36ee0"*/

	inputPath = "testECpriv.pem"
	err = genEccVrf(eccVrf)
	if err != nil {
		t.Errorf("FAIL - EC-VRF Failure: %v", err)
	}
	proofString = fmt.Sprintf("%x, %x, %x, %x", eccVrf.EccProof.X, eccVrf.EccProof.Y, eccVrf.EccProof.C, eccVrf.EccProof.S)
	betaString = fmt.Sprintf("%x", eccVrf.Beta)

	inputPath = "testECpub.pem"
	valid, err = verEccVrf(eccVrf)
	if err != nil {
		t.Errorf("FAIL - EC-VRF Failure: %v", err)
	}
	if valid == false {
		t.Errorf("FAIL - VRF verification failure")
	}
}
