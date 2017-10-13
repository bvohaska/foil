package commands

import (
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"foil/cryptospecials"

	"github.com/spf13/cobra"
)

func init() {

	// Add VRF specific flags
	vrfCmd.PersistentFlags().BoolVarP(&typeRSA, "rsa", "", false, "Use a RSA-based VRF")
	vrfCmd.PersistentFlags().BoolVarP(&typeECC, "ecc", "", false, "Use an ECC-based VRF")
	vrfCmd.PersistentFlags().StringVarP(&alphaString, "alpha", "", "", "Use [string] as VRF input")
	vrfCmd.PersistentFlags().StringVarP(&betaString, "beta", "", "", "Use [string] as H(proof) - Beta")
	vrfCmd.PersistentFlags().StringVarP(&proofString, "proof", "", "", "Use [hex] as VRF proof for validation")
	// Add Gen/Ver specific flags
	vrfGenCmd.PersistentFlags().StringVarP(&pathPriv, "priv", "", "", "Specify path to private key")
	vrfVerCmd.PersistentFlags().StringVarP(&pathPub, "pub", "", "", "Specify path to pub key")

	// Add VRF generate and verify as sub commands of vrf
	vrfCmd.AddCommand(vrfGenCmd)
	vrfCmd.AddCommand(vrfVerCmd)
}

var (
	typeRSA     bool
	typeECC     bool
	pathPriv    string
	pathPub     string
	alphaString string
	betaString  string
	proofString string

	vrfCmd = &cobra.Command{
		Use:               "vrf",
		Short:             "Perform a VRF action",
		Long:              `Foil can perform RSA and ECC VRF operations defined in: https://eprint.iacr.org/2017/099.pdf.`,
		PersistentPreRunE: vrfPreChecks,
		/*Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},*/
	}

	vrfGenCmd = &cobra.Command{
		Use:     "gen [TYPE] [PRIV PEM]",
		Short:   "Generate a VRF proof and data",
		Long:    `Generate a VRF proof and data; [TYPE] is ECC or RSA. PEM file must be unencrypted.`,
		PreRunE: vrfGenChecks,
		RunE:    doGenVRF,
	}

	vrfVerCmd = &cobra.Command{
		Use:     "verify [TYPE] [PUB PEM]",
		Short:   "Verify an RSA-VRF proof and data",
		Long:    `Verify a VRF proof and data; [TYPE] is ECC or RSA.`,
		PreRunE: vrfVerChecks,
		RunE:    doVerVRF,
	}
)

// Perform checks for flags pertaining to VRF options
func vrfPreChecks(cmd *cobra.Command, args []string) error {

	// Ensure that input (PEM) is read from a file
	if len(stdInString) > 0 {
		return errors.New("Error: Reading from StdIn is not permitted when using VRFs - Must read from file")
	}
	// Inform the user that output defaults to StdOut; specifying output direction does nothing
	if len(outputPath) > 0 || stdOutBool {
		return errors.New("Error: Dutput direction not supported in VRF - Ouput will be sent to StdOut")
	}
	// Check to ensure that required flags are set; ensure the user is aware of VRF and PEM types
	if typeRSA == false && typeECC == false {
		return errors.New("Error: Specify the type of VRF to be used: RSA or ECC")
	}
	if pathPriv == "" && pathPub == "" {
		return errors.New("Error: Specify an input PEM (--priv or --pub [path to file])")
	}

	return nil
}

// Perform checks for flags pertaining specifically to VRF generation
func vrfGenChecks(cmd *cobra.Command, args []string) error {

	// Ensure that alpha is provided
	if alphaString == "" {
		return errors.New("Error: Specify VRF input (alpha)")
	}
	return nil
}

// Perform checks for flags pertaining specifically to VRF verification
func vrfVerChecks(cmd *cobra.Command, args []string) error {

	// Ensure that alpha, beta, proof are provided
	if alphaString == "" {
		return errors.New("Error: Specify VRF input (alpha) (hex))")
	}
	if betaString == "" {
		return errors.New("Error: Specify hash of VRF proof (hex)")
	}
	if proofString == "" {
		return errors.New("Error: Specify VRF proof (hex)")
	}
	return nil
}

/*
*
 */
func doGenVRF(cmd *cobra.Command, args []string) error {

	var (
		err error
	)

	if typeRSA {
		err = genRsaVrf()
		if err != nil {
			return err
		}
	} else if typeECC {
		err = genEccVrf()
		if err != nil {
			return err
		}
	}

	return nil
}

func doVerVRF(cmd *cobra.Command, args []string) error {

	var (
		err error
	)

	if typeRSA {
		err = verRsaVrf()
		if err != nil {
			return err
		}
	} else if typeECC {
		err = verEccVrf()
		if err != nil {
			return err
		}
	}

	return nil
}

/*
*  Perform boilerplate operation needed to generate a VRF output given:
*  (1) an alpha (might be shared only with the generator and verifier),
*  (2) RSA private key
 */
func genRsaVrf() error {

	var (
		err     error
		vrfData cryptospecials.RSAVRF
	)

	vrfData.Alpha = []byte(alphaString)

	// Load an RSA private key from file; store in RSAVRF struct
	vrfData.PrivateKey, err = cryptospecials.RSAPrivKeyLoad(&pathPriv, Verbose)
	if err != nil {
		return err
	}

	// Generate a VRF proof and beta (H(proof))
	vrfData.Proof, vrfData.Beta, err = vrfData.Generate(vrfData.Alpha, vrfData.PrivateKey, Verbose)
	if err != nil {
		return err
	}

	// There is currently no standard for VRF output. Printing raw hex to StdIn in the meantime
	fmt.Printf("VRF Proof (hex): %x\n", vrfData.Proof)
	fmt.Printf("VRF Beta - H(Proof) (hex): %x\n", vrfData.Beta)

	return nil
}

func genEccVrf() error {

	fmt.Println("This is a temporary placeholder")

	return nil
}

/*
*  Perform boilerplate operation needed to verify a VRF output given:
*  (1) an alpha (might be shared only with the generator and verifier),
*  (2) beta (public)
*  (3) proof (public)
*  (4) RSA public key of the generator
 */
func verRsaVrf() error {

	var (
		validVRF bool
		err      error
		pubKey   *rsa.PublicKey
		vrfData  cryptospecials.RSAVRF
	)

	vrfData.Alpha = []byte(alphaString)
	// Read beta and proof as hex and store as useable bytes
	vrfData.Proof, err = hex.DecodeString(proofString)
	if err != nil {
		return err
	}
	vrfData.Beta, err = hex.DecodeString(betaString)
	if err != nil {
		return err
	}

	// Load an RSA public key from file
	pubKey, err = cryptospecials.RSAPubKeyLoad(&pathPub, Verbose)
	if err != nil {
		return err
	}
	//vrfData.PublicKey = pubKey //broken // TODO: Fix assignment SegFault

	// Verify that the proof, beta, and alpha are valid // &vrfData.PublicKey changed to pubKey
	validVRF, err = vrfData.Verify(vrfData.Alpha, vrfData.Beta, vrfData.Proof, pubKey, Verbose)
	if err != nil {
		return err
	}

	/*
	*  Inform the user about the VRF validity. There is currently no standard for VRF
	*  output. Printing to StdIn in the meantime.adataString
	 */
	if validVRF {
		fmt.Printf("VRF Proof & Beta are valid\n")
	} else {
		fmt.Printf("VRF Proof & Beta are NOT valid\n")
	}

	return nil
}

func verEccVrf() error {

	fmt.Println("This is a temporary placeholder")

	return nil
}
