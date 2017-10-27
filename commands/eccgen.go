package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"foil/cryptospecials"

	"github.com/spf13/cobra"
)

func init() {

	// Add rsa specific flags
	ecCmd.PersistentFlags().BoolVarP(&ecGen, "gen", "", false, "generate an ECDSA private & public key")
	ecCmd.PersistentFlags().BoolVarP(&ecExtract, "pub", "", false, "extract an ECDSA public key from an ECDSA private PEM")
}

var (
	ecExtract bool
	ecGen     bool

	ecCmd = &cobra.Command{
		Use:               "ecgen [--text/out PATH] [operation]",
		Short:             "Generate an ECDSA private key or extract a public key",
		Long:              `Generate a P-256 ECDSA private key or extract the public key from a private PEM`,
		PersistentPreRunE: ecPreChecks,
		RunE:              doECC,
	}
)

/*
*  Check all of the required flags for rsa command to run successfully. Ensure
*  that there are no flags set that would lead to logical faults.
 */
func ecPreChecks(cmd *cobra.Command, args []string) error {

	if ecGen == false && ecExtract == false {
		return errors.New("Error: Must specify an action --gen/--pub")
	}
	// Check to make sure the appropriate flags are set
	if stdOutBool == false && outputPath == "" {
		return errors.New("Error: Must specify an output method")
	} else if inputPath == "" && ecExtract == true {
		return errors.New("Error: Must specify an input file")
	}

	// ECC will not take StdIn as source input
	if stdInString != "" {
		return errors.New("Error: Reading from StdIn not available for ECC")
	}
	// User must specify an output file when extracting a public key
	if ecExtract == true && outputPath == "" {
		return errors.New("Error: Must specify an output file for the public PEM")
	}

	return nil
}

func doECC(cmd *cobra.Command, args []string) error {

	var (
		err error
	)

	// Ensure that only one options is selected (so no deupulication of input flags is needed)
	if ecGen && ecExtract {
		return errors.New("Error: Select only one option --gen or --pub")
	}

	if ecGen {
		err = genECDSA()
		if err != nil {
			return err
		}
	} else if ecExtract {
		err = extractECDSAPub()
		if err != nil {
			return err
		}
	}

	return nil
}

func genECDSA() error {

	var (
		keyBytes []byte
		err      error
		privKey  *ecdsa.PrivateKey
	)

	// Define the elliptic curve; this can be changed to a flag
	ec := elliptic.P256()

	// Generate an ECDSA private key using P-256
	privKey, err = cryptospecials.EccPrivKeyGen(ec)
	if err != nil {
		return err
	}

	// Save the ECDSA private and public key as as files and/or print to stdin
	if inputPath != "" {
		err = cryptospecials.EccKeySave(privKey, inputPath, inputPath+".pub")
		if err != nil {
			return err
		}
	}
	// Print to StdOut if requested
	if stdOutBool {
		keyBytes, err = x509.MarshalECPrivateKey(privKey)
		keyBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		fmt.Printf("%s\n", keyBytes)
	}
	return nil
}

func extractECDSAPub() error {

	var (
		err     error
		privKey *ecdsa.PrivateKey
	)

	// Load an ECDSA private key
	privKey, err = cryptospecials.EccPrivKeyLoad(inputPath)
	if err != nil {
		return err
	}

	/*
	*  NOTE: This will overwrite the existing private key with the same key
	*  Save the ECDSA pub key as a file and/or print to stdin
	 */
	err = cryptospecials.EccKeySave(privKey, inputPath, outputPath)
	if err != nil {
		return err
	}

	return nil
}
