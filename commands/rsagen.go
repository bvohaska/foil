package commands

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"foil/cryptospecials"

	"github.com/spf13/cobra"
)

func init() {

	// Add rsa specific flags
	rsaCmd.PersistentFlags().IntVarP(&sizeRSA, "size", "", 0, "generate an RSA private key of length [size] bits")
	rsaCmd.PersistentFlags().BoolVarP(&rsaGen, "gen", "", false, "generate an RSA private key")
	rsaCmd.PersistentFlags().BoolVarP(&rsaExtract, "pub", "", false, "extract an RSA public key from an RSA private key PEM")
}

var (
	rsaExtract bool
	rsaGen     bool
	sizeRSA    int

	rsaCmd = &cobra.Command{
		Use:               "rsa [OUT]",
		Short:             "Generate an RSA private key or extract a public key",
		Long:              `Generate an RSA private key with key size [size] or Extract the public key from a private PEM`,
		PersistentPreRunE: rsaPreChecks,
		RunE:              doRSA,
	}
)

/*
*  Check all of the required flags for rsa command to run successfully. Ensure
*  that there are no flags set that would lead to logical faults.
 */
func rsaPreChecks(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("Error: Unknown arguments: %v", args)
	}
	// Check to make sure the appropriate flags are set
	if stdOutBool == false && len(outputPath) == 0 {
		return errors.New("Error: Must specify an output method")
	} else if len(inputPath) == 0 && rsaGen == false {
		return errors.New("Error: Must specify an input file")
	} else if rsaGen == true && sizeRSA == 0 {
		return errors.New("Error: Must specify a key size")
	}

	// Check to make sure the appropriate flags are set
	if stdOutBool == false && len(outputPath) == 0 {
		return errors.New("Error: Must specify an output method")
	}

	// RSA will not take StdIn as source input
	if len(stdInString) > 0 {
		return errors.New("Error: Reading from StdIn not available for RSA")
	}

	return nil
}

func doRSA(cmd *cobra.Command, args []string) error {

	var (
		err error
	)

	// Ensure that only one options is selected (so no deupulication of input flags is needed)
	if rsaGen && rsaExtract {
		return errors.New("Error: Select only one option --gen or --pub")
	}

	if rsaGen {
		err = genRSA()
		if err != nil {
			return err
		}
	} else if rsaExtract {
		err = extractRSAPub()
		if err != nil {
			return err
		}
	}

	return nil
}

func genRSA() error {

	var (
		err     error
		privKey *rsa.PrivateKey
	)

	// Generate an RSA private key with key length of sizeRSA bits
	privKey, err = cryptospecials.RSAKeyGen(sizeRSA)
	if err != nil {
		return err
	}

	// Save the RSA private key as a file and/or print to stdin
	err = cryptospecials.RSAKeySave(privKey, false, stdOutBool, &outputPath, Verbose)
	if err != nil {
		return err
	}

	return nil
}

func extractRSAPub() error {

	var (
		err     error
		privKey *rsa.PrivateKey
	)

	// Load an RSA private key
	privKey, err = cryptospecials.RSAPrivKeyLoad(&inputPath, Verbose)
	if err != nil {
		return err
	}

	// Save the RSA pub key as a file and/or print to stdin
	err = cryptospecials.RSAKeySave(privKey, true, stdOutBool, &outputPath, Verbose)
	if err != nil {
		return err
	}

	return nil
}
