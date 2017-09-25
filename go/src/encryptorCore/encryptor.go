/*
*  Welcome to the AES cli encryption/decryption tool. This tool currently supports only
*  AES-GCM. CGM Mode should NOT be used for encrypting more than 64GB of data. Counter
*  repeats after 2^32 block d/encryptions. This tool supports only 256-bit keys.
*
*		- Brian Vohaska
 */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"encryptorCore/helpers"
)

// cliInputFileLogic determines from where the input text will be drawn
func cliInputFileLogic(cliStdin *string, cliFileSource *string, operation *string, verbose bool) ([]byte, []byte, bool) {
	// Logic for file input - Must have StdIn or SRC flag set or exit program

	var (
		err       error
		iv        []byte
		inputText []byte
	)

	if *operation == "encrypt" {
		iv = make([]byte, 12)
		helpers.GetAESRandomBytes(iv, verbose)
	}

	if len(*cliStdin) > 0 {
		inputText = []byte(*cliStdin)
		if *operation == "decrypt" {
			iv = inputText[:12]
		}
	} else if len(*cliFileSource) > 0 {
		fileStats, _ := os.Stat(*cliFileSource)
		if fileStats.Size() > helpers.MaxFileSize {
			fmt.Println("Error: Source file larger than 64GB; File must be smaller than 64GB")
			return nil, []byte{}, false
		}
		inputText, err = ioutil.ReadFile(*cliFileSource)
		if err != nil {
			fmt.Println("Error: Reading file:", *cliFileSource, "\nError:", err)
			return nil, []byte{}, false
		}
		// Read the first 12 BYTES as the IV for AES
		iv = inputText[:12]
	}

	// Check to see if a null file was passed
	if inputText == nil || len(inputText) == 0 {
		fmt.Println("WARNING: The input source is of length zero")
	}

	return iv, inputText, true
}

// cliOutputFileLogic determines to where the output text will be saved
func cliOutputFileLogic(outputText []byte, cliStdOut *bool, cliFileDestination *string, operation *string, verbose bool) bool {

	if *cliStdOut {
		//Display output to StdIn
		if *operation == "decrypt" {
			fmt.Println("Output plaintext:", string(outputText))
		} else if *operation == "encrypt" {
			fmt.Printf("Output ciphertext (hex): %x\n", outputText)
		} else {
			fmt.Println("Error: Unknown error in displaying text to StdIn ")
		}
	} else if len(*cliFileDestination) > 0 {
		//Write ouptut to file
		err := ioutil.WriteFile(*cliFileDestination, outputText, 0644)
		if err != nil {
			fmt.Println("Error in saving output to file:", err)
			return false
		}
	} else {
		//Display an error if an unknown logic condition occured
		fmt.Println("Please specify a destination for d/encryption")
		return false
	}

	//SUCCESS
	return true
}

// cliKeyLogic determines what key the d/encryptor will use; default is RANDOM key
func cliKeyLogic(cliPassword *string, cliKey *string, verbose bool) ([]byte, bool) {

	var (
		err error
		key []byte
	)

	if len(*cliPassword) > 0 {
		key = helpers.KeyFromPassword(cliPassword, nil, 64, verbose)
	} else if len(*cliKey) > 0 {
		key, err = hex.DecodeString(*cliKey)
		if err != nil {
			fmt.Println("Error: There was an error in cliKeyLogic;", err)
		}
	} else {
		key = make([]byte, 32)
		helpers.GetAESRandomBytes(key, verbose)
		fmt.Println("WARNING: Random key generated and used!")
		fmt.Printf("SECRET - Key: %x/n", key)
	}

	return key, true
}

/*
*  Encryptor was not optimized for large files. There is no streaming file logic in the AESCore function.
*  For larger files try replacing cliInputFileLogic io.ReadFile with something more efficent if possible.
*  NOTE: The iv/nonce will be generated at random for encryption and will be taken as the first 12 BYTES
*  of the input file for decryption. The encryptor will not check to see if you have enought persistant
*  storage space in which to sotre the d/encrypted output; make sure you have enough space.
 */
func main() {

	var (
		mainSuccess bool
		inputText   []byte
		outputText  []byte
		iv          []byte
		key         []byte
	)

	// Read and parse command-line flags. Store them in cliParamters (type CliParams struct)
	cliParameters, mainSuccess := helpers.CliFlags()
	if !mainSuccess {
		fmt.Println("There was a command-line error. Terminating execution.")
		return
	}

	// Determine where the input file will be read from. Set the IV from input.
	iv, inputText, mainSuccess = cliInputFileLogic(cliParameters.CliStdIn, cliParameters.CliFileSource, cliParameters.Operation, *cliParameters.CliVerbose)
	if !mainSuccess {
		fmt.Println("There was a read error. Terminating execution.")
		return
	}

	// Determine whether to accept password, key (hex), or generate a random value
	key, mainSuccess = cliKeyLogic(cliParameters.CliPassword, cliParameters.CliKey, *cliParameters.CliVerbose)
	if !mainSuccess {
		fmt.Println("There was a password error. Terminating execution.")
		return
	}

	// Perform the encryption or decryption operation
	outputText, mainSuccess = helpers.AESCore(iv, key, cliParameters.CliADATA, inputText, *cliParameters.Operation, *cliParameters.CliVerbose)
	if !mainSuccess {
		fmt.Println("There was an AES error. Terminating execution.")
		return
	}

	// TODO: Logic for file output - Must have StdOut or DST flag set or exit program
	mainSuccess = cliOutputFileLogic(outputText, cliParameters.CliStdOut, cliParameters.CliFileDestination, cliParameters.Operation, *cliParameters.CliVerbose)
	if !mainSuccess {
		fmt.Println("There was a file write or StdOut error. Terminating execution.")
		return
	}

}

// TestFramework should be exported to another package
func TestFramework(testCliParameters helpers.CliParams) bool {

	// Test plaintext
	plaintext := []byte("Attack at dawn")

	// Test nonce, iv, key
	nonce := make([]byte, 12)
	aesTrialIv := make([]byte, helpers.BlockSize)
	key := make([]byte, 2*helpers.BlockSize)

	_ = helpers.GetAESRandomBytes(nonce, true)
	_ = helpers.GetAESRandomBytes(aesTrialIv, true)
	_ = helpers.GetAESRandomBytes(key, true)

	// Trial password expansion function
	aesKey := helpers.KeyFromPassword(testCliParameters.CliPassword, nil, 64, true)
	aesIv := aesKey[:12]

	// Test AES encryption and decryption
	encAESResult, encSuccess := helpers.AESCore(aesIv, aesKey, nil, plaintext, "encrypt", true)
	if !encSuccess {
		fmt.Println("Error in TEST ENCRYPTION:", encSuccess)
	}
	decAESResult, decSuccess := helpers.AESCore(aesIv, aesKey, nil, encAESResult, "decrypt", true)
	if !decSuccess {
		fmt.Println("Error in TEST DECRYPTION:", decSuccess)
	}

	// Print results to STDIN
	fmt.Printf("TestFramework - Ciphertext Output: %x\n", encAESResult)
	fmt.Printf("TestFramework - Plaintext Output: \"%s\"\n", decAESResult)

	// Test AES construction primitives
	aesBlock, _ := aes.NewCipher(aesKey)
	aesGCM, _ := cipher.NewGCM(aesBlock)

	ciphertext := aesGCM.Seal(nil, aesIv, plaintext, nil)
	fmt.Printf("TestFramework - From primitives - Ciphertext is: %x\n", ciphertext)

	cipherString := string(ciphertext)
	encAESRString := string(encAESResult)
	if cipherString == encAESRString {
		fmt.Println("TEST RESULTS - No Errors. The ciphertexts from primitives and AESCore ARE the same")
	} else {
		fmt.Println("TEST RESULTS - No Errors. The ciphertexts from primitives and AESCore ARE NOT the same")
	}
	return true
}

//TODO: Check the 12/16 byte IV requirement
//TODO: Fix file IO stream for AESCore
//TODO: Automated testing framework, statespace traversal, and fuzzer

/*
*	//Testing Code


	//KeyFrom Passowrd:
		fmt.Printf("Password is of type %T and has value %s\n", password, *password)
	//Main
		password := []byte("LegitPassword2")
		keyExpand := pbkdf2.Key(password, []byte{}, 64, 32, sha256.New)
		fmt.Printf("The key from main loop is: %x\n", keyExpand)
		fmt.Printf("The information in cliPassword is: \"%s\" of type %T\n", *cliParameters.cliPassword, cliParameters.cliPassword)


*/
