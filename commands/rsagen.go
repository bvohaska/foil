package commands

import (
	"crypto/rsa"
	"errors"
	"foil/cryptospecials"

	"github.com/spf13/cobra"
)

func init() {

	// Add rsa specific flags
	rsaCmd.PersistentFlags().IntVarP(&sizeRSA, "size", "", 0, "Generate an RSA private key of length [SIZE] bits")
	rsaCmd.PersistentFlags().BoolVarP(&rsaGen, "gen", "", false, "Generate an RSA private key")
	rsaCmd.PersistentFlags().BoolVarP(&rsaExtract, "pub", "", false, "Extract an RSA public key from an RSA private key PEM")
}

var (
	rsaExtract bool
	rsaGen     bool
	sizeRSA    int

	rsaCmd = &cobra.Command{
		Use:               "rsa [OUT]",
		Short:             "Generate an RSA private key or Extract a public key",
		Long:              `Generate an RSA private key with key size [SIZE] or Extract the public key from a private PEM`,
		PersistentPreRunE: rsaPreChecks,
		RunE:              doRSA,
	}
)

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
