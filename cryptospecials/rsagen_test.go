package cryptospecials

import (
	"crypto/rsa"
	"testing"
)

// test for zeros
/*
*  Test to ensure that:
*  (1) Short RSA keys are rejected
*  (2) Non-standard RSA moduli are rejected; they must be 2048, 3072, or 4096
*  (3) RSA primes are indeed prime with probability (1-(1/4)^-64); Miller-Rabin Test
 */
func TestRSAKeyGen(t *testing.T) {

	var (
		testKey *rsa.PrivateKey
		err     error
	)

	testKey, err = RSAKeyGen(1024)
	if err == nil {
		t.Errorf("FAIL - Short key size test failed")
	}

	testKey, err = RSAKeyGen(2049)
	if err == nil {
		t.Errorf("FAIL - No warning to user concerning non-standard key sizes")
	}

	testKey, err = RSAKeyGen(2048)
	if err != nil {
		t.Errorf("FAIL - Fail on normal operation - %v", err)
	}

	if testKey.Primes[0].ProbablyPrime(64) == false || testKey.Primes[1].ProbablyPrime(64) == false {
		t.Errorf("FAIL - RSA modulus is divisible by non-primes")
	}
}

/*
*  Incomplete test. Requires test vectors. Test will FAIL in current form.
*  Note: MGF1 uses SHA-1. This implementation uses SHA-256
 */
/*
 func TestMGF1(t *testing.T) {

	var (
		testVector1      []byte
		testVector2      []byte
		referenceOutput1 []byte
		referenceOutput2 []byte
	)

	testVector1 = []byte("Value of test vector 1")
	testVector2 = []byte("Value of test vector 2")
	referenceOutput1 = []byte("Value of output reference 1")
	referenceOutput2 = []byte("Value of output reference 2")
	h := sha256.New()
	outputTest := make([]byte, 256) // 256 bytes == (2048 bits) / 8

	mgf1XOR(outputTest, h, testVector1)
	if bytes.Compare(outputTest, referenceOutput1) != 0 {
		t.Errorf("FAIL - Test vector ourput did not equal reference value 1 ")
	}

	h.Reset() // Reset state of SHA-256 hash function
	mgf1XOR(outputTest, h, testVector2)
	if bytes.Compare(outputTest, referenceOutput2) != 0 {
		t.Errorf("FAIL - Test vector ourput did not equal reference value 2 ")
	}

	//fmt.Printf("The length of output is: %d\n The output is: %x\n", len(outputTest), outputTest)
}
*/

func TestRSAKeySave(t *testing.T) {

	// Read output destination from StdIn
	/*
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Where should I save the RSA PEM file? :")

		dest, err := reader.ReadString('\n')
		if err != nil {
			t.Errorf("Error: %v", err)
		}
	*/

	// Test saving a RSA private key
	dest := "IAMAPrivKeyTest.pem"
	privKey, err := RSAKeyGen(2048)
	err = RSAKeySave(privKey, false, false, &dest, false)
	if err != nil {
		t.Errorf("FAIL - %v\n", err)
	}

	// Test saving a RSA public key
	dest = "IAMAPubKeyTest.pem"
	err = RSAKeySave(privKey, true, false, &dest, true)
	if err != nil {
		t.Errorf("FAIL - %v\n", err)
	}

}

func TestRSAKeyLoad(t *testing.T) {

	// Read output destination from StdIn
	/*
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Where should I save the RSA PEM file? :")

		dest, err := reader.ReadString('\n')
		if err != nil {
			t.Errorf("Error: %v", err)
		}
	*/

	// Test saving a RSA private key
	dest := "IAMAPrivKeyTest.pem"
	privKey, errPriv := RSAPrivKeyLoad(&dest, false)
	if errPriv != nil {
		t.Errorf("FAIL - %v\n", errPriv)
	}
	validateErr := privKey.Validate()
	if validateErr != nil {
		t.Errorf("FAIL - %v\n", errPriv)
	}

	// Test saving a RSA public key
	dest = "IAMAPubKeyTest.pem"
	pubKey, errPub := RSAPubKeyLoad(&dest, false)
	if errPub != nil {
		_ = pubKey
		t.Errorf("FAIL - %v\n", errPub)
	}

}
