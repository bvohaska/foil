/*
*  Welcome to the AES cli encryption/decryption tool. This tool currently supports only
*  AES-GCM. CGM Mode should NOT be used for encrypting more than 64GB of data. Counter
*  repeats after 2^32 block d/encryptions. This tool supports only 256-bit keys.
*
*		- Brian Vohaska
*
*
*  Encryption/Decryption in this application (GCM) was not optimized for large files.
*  There is no streaming file logic in the AESCore function.
*  For larger files try replacing cliInputFileLogic io.ReadFile with something more efficent if possible.
*  NOTE: The iv/nonce will be generated at random for encryption and will be taken as the first 12 BYTES
*  of the input file for decryption. The encryptor will not check to see if you have enought persistant
*  storage space in which to sotre the d/encrypted output; make sure you have enough space. Note: The
*  password KDF expects ASCII character input. It WILL parse unicode-8 but this functionallity has not yet
*  been extensively tested.
 */

package commands

import (
	"errors"
	"fmt"
	"foil/helpers"

	"github.com/spf13/cobra"
)

func init() {

	// Define flags used by all sub commands
	aesCmd.PersistentFlags().StringVarP(&keyString, "key", "k", "", "use [hex] as the KEY for AES-GCM")
	aesCmd.PersistentFlags().StringVarP(&passwordString, "password", "p", "", "use [string] (--> PBKDF2) as  KEY for AES-GCM")
	// Define flags used by Encrypt/Decrypt sub commands
	encryptCmd.PersistentFlags().StringVarP(&adataString, "adata", "", "", "use [string] as ADATA for AES-GCM")
	decryptCmd.PersistentFlags().StringVarP(&adataString, "adata", "", "", "use [string] as ADATA for AES-GCM")

	// Add encrypt and decrypt to aesCmd
	aesCmd.AddCommand(encryptCmd)
	aesCmd.AddCommand(decryptCmd)
}

var (
	adataString    string
	passwordString string
	keyString      string

	aesCmd = &cobra.Command{
		Use:               "aes",
		Short:             "Encrypt or decrypt input with AES-256-GCM",
		Long:              ``,
		PersistentPreRunE: aesPreChecks,
	}

	encryptCmd = &cobra.Command{
		Use:   "enc [IN] [OUT]",
		Short: "Encrypt input with AES-256-GCM",
		Long:  ``,
		RunE:  enc,
	}

	decryptCmd = &cobra.Command{
		Use:   "dec [KEY] [IN] [OUT]",
		Short: "Decrypt input with AES-256-GCM",
		Long:  ``,
		RunE:  dec,
	}
)

/*
*  Check all of the required flags for the encrypt and decrypt commands to run
*  successfully. Ensure that there are no flags set that would lead to logical faults
 */
func aesPreChecks(cmd *cobra.Command, args []string) error {

	err := stdChecks(0, 5, cmd, args)
	if err != nil {
		return err
	}

	return nil
}

/*
*  Perform all required boilerplate operations for AES-256-GCM encryption. This is the main
*  functional component of the AES operations. symmetricBoilerPlate combines functions
*  from helpers.go into a form where encryption and decryption can be performed.
 */
func symmetricBoilerPlate(operation *string) error {

	var (
		encSuccess bool
		key        []byte
	)

	// Determine where the input file will be read from. Set the IV from input.
	iv, inputText, encSuccess := helpers.CliInputFileLogic(&stdInString, &inputPath, operation, Verbose)
	if !encSuccess {
		return errors.New("There was a file read or StdIn error. Terminating execution")
	}

	// Determine whether to accept password, key (hex), or generate a random value
	key, encSuccess = helpers.CliKeyLogic(&passwordString, &keyString, operation, Verbose)
	if !encSuccess {
		return errors.New("There was a password error. Terminating execution")
	}

	// Perform the encryption or decryption operation
	outputText, mainError := helpers.AESCore(iv, key, &adataString, inputText, operation, Verbose)
	if mainError != nil {
		return fmt.Errorf("There was an AES error. Terminating execution: %v", mainError)
	}

	// Write the resulting output to: (1) StdOut, or (2) a file set by -target
	encSuccess = helpers.CliOutputFileLogic(outputText, &stdOutBool, &outputPath, operation, Verbose)
	if !encSuccess {
		return errors.New("There was a file write or StdOut error. Terminating execution")
	}

	return nil
}

// Perform AES-256-GCM encryption
func enc(cmd *cobra.Command, args []string) error {

	var (
		operation string
	)

	operation = "encrypt"

	// Provide Addtional flag checks
	// Warn user if encrypting but not providing key material
	if len(passwordString) == 0 && len(keyString) == 0 {
		fmt.Println("WARNING: No key specified; A randomly generated key will be used")
	}

	symmetricBoilerPlate(&operation)

	return nil
}

// Perform AES-256-GCM encryption
func dec(cmd *cobra.Command, args []string) error {

	var (
		operation string
	)

	operation = "decrypt"

	// Provide Addtional flag checks
	if len(passwordString) == 0 && len(keyString) == 0 {
		return errors.New("Error: No key specified")
	}

	symmetricBoilerPlate(&operation)

	return nil
}
