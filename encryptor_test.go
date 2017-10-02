/*
*
*
*/

package main

import (
	"testing"
	"encryptorcore/helpers"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
) 

/*
*  Basic expected input-output test for AESRandomBytes
*/
func TestAESRandomBytes (t *testing.T) {

	var (
		toughTests bool
		successSlice []int
		trialRandom []byte
	)
	toughTests = true

	
	if toughTests {
		for i := 0; i < 129; i++{
			trialRandom = make([]byte, i)
			didISucceed := helpers.GetAESRandomBytes(trialRandom, false)
			if didISucceed == nil {
				successSlice = append(successSlice, i)
			}
		}
		for _, value := range successSlice {
			if value == 12 || value == 16 || value == 32 {
				fmt.Printf("PASS - GetAESRandomBytes: %d bytes\n", value)
			} 
		}

		if len(successSlice) != 3 || successSlice[0] != 12 || successSlice[1] != 16 || successSlice[2] != 32 {
			t.Errorf("FAIL - Test failed: Expected only bytes slices of 12, 16, 32. Received something else.")
		}
	}

}

/*
*  Test expected output of AESCore vs manual AES operations
*/
func TestAESCore (t *testing.T) {

	/* AES Test vectors: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
	key := 53382df51d7d4d17964e178d9ccb2dea7ae8e2238c3a91a392d53fba523f48c4
	iv := ede60d67a345d2be699d3b24
	pt := 7e14b6a5b616ce97e02f9377002786a5
	ct: = 5c4ba32d35959c7e9e94a1f9c0a5c2e0
	*/
	//adata := nil

	var (
		aesKey []byte
		aesIV []byte

		plaintext string
		password string
		
		verbose bool
	)
	
	verbose = false
	// Test Plaintext
	plaintext = "Attack at dawn! I have special characters: !@#(%*U@#)$(_+!@#_|||&&DROPFILLSELECT. This is the end of text"
	// Test Password
	password = "LegitPassword2"
	// Expand test password and build insecure IV
	aesKey = helpers.KeyFromPassword(&password, nil, 64, verbose)
	aesIV = aesKey[:12]

	// Test AES encryption and decryption
	encAESResult, encError := helpers.AESCore(aesIV, aesKey, nil, []byte(plaintext), "encrypt", verbose)
	if encError != nil {
		fmt.Println("Error in TEST ENCRYPTION:", encError)
	}
	decAESResult, decError := helpers.AESCore(aesIV, aesKey, nil, encAESResult, "decrypt", verbose)
	if decError != nil {
		fmt.Println("Error in TEST DECRYPTION:", decError)
	}

	// Test AES construction primitives
	aesBlock, _ := aes.NewCipher(aesKey)
	aesGCM, _ := cipher.NewGCM(aesBlock)

	// Manual AES GCM operation
	ciphertext := aesGCM.Seal(nil, aesIV, []byte(plaintext), nil)

	// Compare ciphertexts -- removing first 12 bytes of encAESResult (IV)
	cipherString := string(ciphertext)
	encAESRString := string(encAESResult[12:])

	if cipherString != encAESRString {
		t.Errorf("FAIL - Test expected AESCore enc/dec plaintext to be equivalent. They were not:")
		fmt.Printf("TestFramework - Manual Ciphertext Output: %x\n", cipherString)
		fmt.Printf("TestFramework - AESCore Ciphertext Output: \"%s\"\n", encAESResult)
	}

	plaintext2 := string(decAESResult)
	if plaintext != plaintext2 {
		t.Errorf("FAIL - plaintext before and after enc/dec are not equivalent.")
		fmt.Println("Plaintext:", plaintext)
		fmt.Println("Plaintext after decryption:",plaintext2)
	}
}


// TestKeyFromPassword should be exported to another package
//func TestKeyFromPassword () {}


//TODO: Determine if it is possible to use Seal()/Open() on a file stream to give memory performance (size) optimization 
//TODO: Automated testing framework, statespace traversal, and fuzzer