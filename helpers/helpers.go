/*
*  Welcome to the AES cli encryption/decryption helper core. The functions contained herein
*  are the true heart of the AES cli encryption/decryption tool. NOTE: AES Core only accepts
*  12 BYTE IVs (nonces) and appends the IV/nonce to the beginning of the ouput file when
*  encryption is chosen as the desired operation. If using command-line provided string for
*  decryption, the 12 BYTE IV/nonce must be the first 12 BYTES of the string AND the string
*  must be hex.
*
*		- Brian Vohaska
 */

package helpers

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

//CliInputFileLogic is an exportable FUNCTION
/*
*  cliInputFileLogic determines from where the input text will be drawn. The logic that
*  checks to ensure mutually exclusive flags are not set exists in CliFlags().
*  The IV/nonce for AES will be generated in this function. There is no defauilt IV/nonce
*  scheme for decryption. Default IV/nonce behaviour for encryption is randomly generating
*  an IV/nonce and printing the IV/nonce as the fist 12 bytes of ciphertext.
 */
func CliInputFileLogic(cliStdin *string, cliFileSource *string, operation *string, verbose bool) ([]byte, []byte, bool) {

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
		if fileStats.Size() > MaxFileSize {
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
		err := GetAESRandomBytes(iv, verbose)
		if err != nil {
			fmt.Println(err)
		}
	} else if *operation == "decrypt" {
		iv = inputText[:12]
	}

	// SUCCESS
	return iv, inputText, true
}

//CliOutputFileLogic is an exportable FUNCTION
/*
*  cliOutputFileLogic determines whether the output text will be printed to StdOut or saved
*  as a file. The logic that checks to ensure mutually exclusive flags are not set exists in
*  CliFlags().
 */
func CliOutputFileLogic(outputText []byte, cliStdOut *bool, cliFileDestination *string, operation *string, verbose bool) bool {

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

//CliKeyLogic is an exportable FUNCTION
/*
*  cliKeyLogic determines what key the d/encryptor will use; default is RANDOM key. The logic
*  that checks to ensure mutually exclusive flags are not set exists in CliFlags(). This
*  function is designed to have a default return of FAIL. Do not want key parsing or generation
*  to fail silently. Note: This function does yet support salting of hashes.
 */
func CliKeyLogic(cliPassword *string, cliKey *string, cliOperation *string, verbose bool) ([]byte, bool) {

	var (
		err                error
		minSecureKeyLength int
		key                []byte
	)

	/*
	*  Set the minimum length of the input password.
	*  (16 bytes) * (7 bits/rand char ASCII) = 112 bits or less of security
	*  112 bits is approximately the security parameter of ~RSA-2048
	 */
	minSecureKeyLength = 16

	/*
	*  WARNING: This block heavily relies on the logical input checking correctness of
	*  CliFlags().
	*  WARNING: This block will not prevent a user from using a short or weak password.
	*
	*  Take care in editing the logic in CliFlags(). This block will first determine
	*  if the user provided a password. If so, the block will check for password length issues
	*  (minimum security threshold) and warn the user if the password is short. If the user
	*  has selected to provide a key (must be hex!), the block will check to ensure the key
	*  is 256 bits (32 bytes) or print an error otherwise. If the user has selected neither CLI
	*  flag AND has selected encryption, the block will generate a random 256-bit key otherwise
	*  an error will be printed. This block is designed with a default failure mode. This is
	*  done to ensure that no key is generated that is unintentional or logically compromised.
	 */
	if len(*cliPassword) > 0 {
		if len(*cliPassword) < minSecureKeyLength {
			fmt.Println("Warning: The password supplied has less than 112 bits (As hard as RSA-2048) of security")
		}
		key = KeyFromPassword(cliPassword, nil, 64, verbose)
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
		if *cliOperation == "encrypt" {
			key = make([]byte, 32)
			err := GetAESRandomBytes(key, verbose)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("WARNING: Random key generated and used!")
			fmt.Printf("SECRET - Key: %x\n", key)
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
