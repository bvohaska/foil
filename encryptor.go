/*
*  Welcome to the AES cli encryption/decryption tool. This tool currently supports only
*  AES-GCM. CGM Mode should NOT be used for encrypting more than 64GB of data. Counter
*  repeats after 2^32 block d/encryptions. This tool supports only 256-bit keys.
*
*		- Brian Vohaska
*
*  Quick summary of cli flags (type --help if you have already built the application):
*
*		-adata string
*			Provide ASCII additional authenticated data following -adata
*		-decrypt
*			Instruct the applicatiion to perform decryption
*		-encrypt
*			Instruct the application to perform encryption
*		-key string
*			Instruct the applicatiion to use a user provided key (hex only)
*		-password string
*			Instruct the application to use the ASCII password following -password
*		-source string
*			Set the location of the input file
*		-target string
*			Set the target location of the output file
*		-textin string
*			Use the string "[STRING]" following -txtin as the source file
*		-textout
*			Print output to stdin
*		-verbose
*			Verbose Mode - reveals most of the internal variable state
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

/* 
*  cliInputFileLogic determines from where the input text will be drawn. The logic that
*  checks to ensure mutually exclusive flags are not set exists in helpers.CliFlags().
*  The IV/nonce for AES will be generated in this function. There is no defauilt IV/nonce
*  scheme for decryption. Default IV/nonce behaviour for encryption is randomly generating
*  an IV/nonce and printing the IV/nonce as the fist 12 bytes of ciphertext.
*/
func cliInputFileLogic(cliStdin *string, cliFileSource *string, operation *string, verbose bool) ([]byte, []byte, bool) {

	var (
		err       error
		iv        []byte
		inputText []byte
	)

	/* 
	*  WARNING: Passing more than 64GB of data will force a counter reapeat that could leak plaintext 
	*  WARNING: **This block will read the ENTIRE file into memory for processing** large files
	*  could lead to errors.
	*
	*  This block attempts to first read input text from StdIn input. If the -target flag is set, 
	*  this block will check the file's SIZE to ensure that the file is less than 64GB. 
	 */
	if len(*cliStdin) > 0 {
		inputText = []byte(*cliStdin)		
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
	} else {
		fmt.Println("Error: Unknown error occured in cliInputFileLogic")
		return nil, []byte{}, false
	}

	// Check to determine if an empty file was passed to the application. If so, Warn the user.
	if inputText == nil || len(inputText) == 0 {
		fmt.Println("WARNING: The input source is of length zero")
	}

	/*
	*  Given the CliFlasg set, determine if the IV/nonce should be randomly generated or extracted from
	*  the input text; random generation will only occur for encryption. If decryption is selected then
	*  (1) Either read the first 12 BYTES from StdIn input as IV/nonce if the -textin flag was set or,
	*  (2) Read the first 12 BYTES of FILE as the IV/nonce if the -source flag was set. 
	*/
	if *operation == "encrypt" {
		iv = make([]byte, 12)
		helpers.GetAESRandomBytes(iv, verbose)
	} else if *operation == "decrypt" {
		iv = inputText[:12]
	}

	// SUCCESS
	return iv, inputText, true
}

/*
*  cliOutputFileLogic determines whether the output text will be printed to StdOut or saved
*  as a file. The logic that checks to ensure mutually exclusive flags are not set exists in
*  helpers.CliFlags().
*/
func cliOutputFileLogic(outputText []byte, cliStdOut *bool, cliFileDestination *string, operation *string, verbose bool) bool {

	/*
	*  The block will first determine if the -textout flag is set. If so, the block will
	*  print attempt to present the output in a readable format: (1) hex if ciphertext, or
	*  (2) as a string if plaintext. If the -target flag is set, the block will attempt to 
	*  open a file with the path set to the string following -target. If the opening operation
	*  is successfull, the block will write the ENTIRE ouptut to the file. This block will 
	*  print an error if an unknown logic condition occurs.
	*/
	if *cliStdOut {
		if *operation == "decrypt" {
			fmt.Println("Output plaintext:", string(outputText))
		} else if *operation == "encrypt" {
			fmt.Printf("Output ciphertext (hex): %x\n", outputText)
		} else {
			fmt.Println("Error: Unknown error in displaying output text to StdIn")
			return false
		}
	} else if len(*cliFileDestination) > 0 {
		err := ioutil.WriteFile(*cliFileDestination, outputText, 0644)
		if err != nil {
			fmt.Println("Error in saving output to file:", err)
			return false
		}
	} else {
		fmt.Println("Please specify a destination for d/encryption")
		return false
	}

	//SUCCESS
	return true
}

/* 
*  cliKeyLogic determines what key the d/encryptor will use; default is RANDOM key. The logic 
*  that checks to ensure mutually exclusive flags are not set exists in helpers.CliFlags(). This
*  function is designed to have a default return of FAIL. Do not want key parsing or generation
*  to fail silently.
*/
func cliKeyLogic(cliPassword *string, cliKey *string, cliOperation *string, verbose bool) ([]byte, bool) {

	var (
		err error
		minSecureKeyLength int
		key []byte
	)

	/*
	*  Set the minimum length of the input password. 
	*  (16 bytes) * (7 bits/rand char ASCII) = 112 bits or less of security 
	*  112 bits is approximately the security parameter of ~RSA-2048
	*/
	minSecureKeyLength = 16  

	/*
	*  WARNING: This block heavily relies on the logical input checking correctness of 
	*  helpers.CliFlags(). 
	*  WARNING: This block will not prevent a user from using a short or weak password.
	*  
	*  Take care in editing the logic in helpers.CliFlags(). This block will first determine
	*  if the user provided a password. If so, the block will check for password length issues 
	*  (minimum security threshold) and warn the user if the password is short. If the user 
	*  has selected to provide a key (must be hex!), the block will check to ensure the key 
	*  is 256 bits (32 bytes) or print an error otherwise. If the user has selected neither CLI
	*  flag AND has selected encryption, the block will generate a random 256-bit key otherwise 
	*  an error will be printed. This block is designed with a default failure mode. This is 
	*  done to ensure that no key is generated that is unintentional or logically compromised.
	*/
	if len(*cliPassword) > 0 {
		if len(*cliPassword) < minSecureKeyLength{
			fmt.Println("Warning: The password supplied has less than 112 bits (As hard as RSA-2048) of security")
		}
		key = helpers.KeyFromPassword(cliPassword, nil, 64, verbose)
		return key, true
	} else if len(*cliKey) > 0 {
		key, err = hex.DecodeString(*cliKey)
		if err != nil {
			fmt.Println("Error: There was an error in cliKeyLogic;", err)
			return []byte{}, false
		} else if len(key) < 32 {
			fmt.Println("Error: The key provided is of length < 256 bits!")
			return []byte{}, false
		} else if len(key) > 32 {
			fmt.Println("Error: The key provided is of length > 256 bits!")
			return []byte{}, false
		}
		return key, true
	} else {
		if *cliOperation == "encrypt"{
			key = make([]byte, 32)
			helpers.GetAESRandomBytes(key, verbose)
			fmt.Println("WARNING: Random key generated and used!")
			fmt.Printf("SECRET - Key: %x/n", key)
			return key, true
		} else if *cliOperation == "decrypt" {
			fmt.Println("Error: No decyrption key given")
			return []byte{}, false
		} else {
			fmt.Println("Error: Unknown error in cliKeyLogic")
			return []byte{}, false
		}
	}

	// This section is intentionally logically unreachable given the if/else statements above
	//return []byte{}, false 
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
		fmt.Println("There was a file read or StdIn error. Terminating execution.")
		return
	}

	// Determine whether to accept password, key (hex), or generate a random value
	key, mainSuccess = cliKeyLogic(cliParameters.CliPassword, cliParameters.CliKey, cliParameters.Operation, *cliParameters.CliVerbose)
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

	// Write the resulting output to: (1) StdOut, or (2) a file set by -target
	mainSuccess = cliOutputFileLogic(outputText, cliParameters.CliStdOut, cliParameters.CliFileDestination, cliParameters.Operation, *cliParameters.CliVerbose)
	if !mainSuccess {
		fmt.Println("There was a file write or StdOut error. Terminating execution.")
		return
	}

}

// testFramework tests the exported fucntions from the helpers package
func testFramework(testCliParameters helpers.CliParams, toughTests bool) bool {

	type answers struct {
		index int
		success bool
	}

	// Generate a test plaintext
	plaintext := []byte("Attack at dawn! I have special characters: !@#(%*U@#)$(_+!@#_|||&&DROPFILLSELECT. This is the end of text")

	// Simple test: GetAESRandomBytes
	// Generate a test nonce, iv, key
	nonce := make([]byte, 12)
	aesTrialIv := make([]byte, helpers.BlockSize)
	key := make([]byte, 2*helpers.BlockSize)
	_ = helpers.GetAESRandomBytes(nonce, true)
	_ = helpers.GetAESRandomBytes(aesTrialIv, true)
	_ = helpers.GetAESRandomBytes(key, true)

	// Hard test: GetAESRandomBytes
	if toughTests {
		var successSlice []int
		for i := 0; i < 129; i++{
			trialRandom := make([]byte, i)
			didISucceed := helpers.GetAESRandomBytes(trialRandom, false)
			if didISucceed {
				successSlice = append(successSlice, i)
			}
		}
		for _, value := range successSlice {
			if value == 12 || value == 16 || value == 32 {
				fmt.Printf("Pass - difficult GetAESRandomBytes: %d bytes", value)
			} else{
				fmt.Printf("Fail - difficult GetAESRandomBytes: %d bytes", value)
			}
		}
	}

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

//TODO: Fix file IO stream for AESCore
//TODO: Automated testing framework, statespace traversal, and fuzzer