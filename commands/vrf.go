package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"foil/cryptospecials"
	"strings"

	"github.com/spf13/cobra"
)

func init() {

	// Add VRF specific flags
	vrfCmd.PersistentFlags().BoolVarP(&typeRSA, "rsa", "", false, "use a RSA-based VRF")
	vrfCmd.PersistentFlags().BoolVarP(&typeECC, "ecc", "", false, "use an ECC-based VRF")
	vrfCmd.PersistentFlags().StringVarP(&alphaString, "alpha", "", "", "use [string] as VRF input")
	vrfCmd.PersistentFlags().StringVarP(&betaString, "beta", "", "", "use [string] as H(proof) - Beta")
	vrfCmd.PersistentFlags().StringVarP(&proofString, "proof", "", "", "use [hex] as VRF proof for validation")
	// Add Gen/Ver specific flags
	vrfGenCmd.PersistentFlags().StringVarP(&pathPriv, "priv", "", "", "specify path to private key")
	vrfVerCmd.PersistentFlags().StringVarP(&pathPub, "pub", "", "", "specify path to pub key")
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
	}

	vrfGenCmd = &cobra.Command{
		Use:     "gen [--rsa/ecc] [private PEM]",
		Short:   "Generate a VRF proof and data",
		Long:    `Generate a VRF proof and data; [TYPE] is ECC or RSA. PEM file must be unencrypted.`,
		PreRunE: vrfGenChecks,
		RunE:    doGenVRF,
	}

	vrfVerCmd = &cobra.Command{
		Use:     "verify [--rsa/ecc] [public PEM]",
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
	if len(proofString) < 64 && typeECC == true {
		return errors.New("Error: Specify VRF proof - (x, y, c, s) - as ([hex], [hex], [hex], [hex])")
	}
	return nil
}

//Using user input, choose which type of VRF output to generate
func doGenVRF(cmd *cobra.Command, args []string) error {

	var (
		err   error
		proof []byte
		beta  []byte
	)

	if typeRSA {
		proof, beta, err = genRsaVrf()
		if err != nil {
			return err
		}
		fmt.Printf("RSA-VRF Proof           (hex): %x\n", proof)
		fmt.Printf("RSA-VRF Beta - H(Proof) (hex): %x\n", beta)
	} else if typeECC {
		eccVrf := cryptospecials.ECCVRF{}
		err = genEccVrf(&eccVrf)
		if err != nil {
			return err
		}
		fmt.Printf("EC-VRF Proof - x, y, c, s (hex): %x, %x, %x, %x\n", eccVrf.EccProof.X, eccVrf.EccProof.Y, eccVrf.EccProof.C, eccVrf.EccProof.S)
		fmt.Printf("EC-VRF Beta H(Proof) (hex): %x\n", eccVrf.Beta)
	}

	return nil
}

// Using user input, choose which type of VRF input to verify
func doVerVRF(cmd *cobra.Command, args []string) error {

	var (
		validVRF bool
		err      error
	)

	if betaString == "" {
		return errors.New("Error: Specify beta H(proof)")
	}

	if typeRSA {
		validVRF, err = verRsaVrf()
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
	} else if typeECC {
		var eccVrf *cryptospecials.ECCVRF
		eccVrf = new(cryptospecials.ECCVRF)
		validVRF, err = verEccVrf(eccVrf)
		if err != nil {
			return fmt.Errorf("Error: Specify VRF proof (x, y, c, s) as \"[hex], [hex], [hex], [hex]\"; %v", err)
		}
		if validVRF {
			fmt.Printf("VRF Proof & Beta are valid\n")
		} else {
			fmt.Printf("VRF Proof & Beta are NOT valid\n")
		}
	}

	return nil
}

/*
*  Perform boilerplate operation needed to generate a VRF output given:
*  (1) an alpha (might be shared only with the generator and verifier),
*  (2) RSA private key (PEM format)
 */
func genRsaVrf() ([]byte, []byte, error) {

	var (
		err     error
		vrfData cryptospecials.RSAVRF
	)

	vrfData.Alpha = []byte(alphaString)

	// Load an RSA private key from file; store in RSAVRF struct
	vrfData.PrivateKey, err = cryptospecials.RSAPrivKeyLoad(&pathPriv, Verbose)
	if err != nil {
		return nil, nil, err
	}

	// Generate a VRF proof and beta (H(proof))
	vrfData.Proof, vrfData.Beta, err = vrfData.Generate(vrfData.Alpha, vrfData.PrivateKey, Verbose)
	if err != nil {
		return nil, nil, err
	}

	// There is currently no standard for VRF output. Printing raw hex to StdIn in the meantime
	return vrfData.Proof, vrfData.Beta, nil
}

/*
* NOTE: Currently only supporting P-256
*  Perform boilerplate operation needed to generate a VRF output given:
*  (1) an alpha (might be shared only with the generator and verifier),
*  (2) EC private key (ECDSA PEM format)
 */
func genEccVrf(eccVrf *cryptospecials.ECCVRF) error {

	var (
		ec      elliptic.Curve
		privKey *ecdsa.PrivateKey
		err     error
	)
	// Define the elliptic curve to be P-256
	ec = elliptic.P256()

	// Load a private key
	privKey, err = cryptospecials.EccPrivKeyLoad(pathPriv)
	if err != nil {
		return err
	}
	eccVrf.EccProof, eccVrf.Beta, err = eccVrf.Generate(sha256.New(), ec, privKey, []byte(alphaString), Verbose)
	if err != nil {
		return err
	}
	if Verbose {
		fmt.Println("EC-VRF Proof: ", eccVrf.EccProof)
	}
	return nil
}

/*
*  Perform boilerplate operation needed to verify a VRF output given:
*  (1) an alpha (might be shared only with the generator and verifier),
*  (2) beta (public)
*  (3) proof (public)
*  (4) RSA public key of the generator (PEM format)
 */
func verRsaVrf() (bool, error) {

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
		return false, err
	}
	vrfData.Beta, err = hex.DecodeString(betaString)
	if err != nil {
		return false, err
	}

	// Load an RSA public key from file
	pubKey, err = cryptospecials.RSAPubKeyLoad(&pathPub, Verbose)
	if err != nil {
		return false, err
	}
	//vrfData.PublicKey = pubKey //broken // TODO: Fix assignment SegFault

	// Verify that the proof, beta, and alpha are valid // &vrfData.PublicKey changed to pubKey
	validVRF, err = vrfData.Verify(vrfData.Alpha, vrfData.Beta, vrfData.Proof, pubKey, Verbose)
	if err != nil {
		return false, err
	}

	return validVRF, nil
}

/*
* NOTE: Currently only supporting P-256
*  Perform boilerplate operation needed to verify a VRF output given:
*  (1) an alpha (might be shared only with the generator and verifier),
*  (2) beta (public)
*  (3) proof (public)
*  (4) EC public key (ECDSA PEM format)
 */
func verEccVrf(eccVrf *cryptospecials.ECCVRF) (bool, error) {

	var (
		valid  bool
		swap   []byte
		ec     elliptic.Curve
		pubKey *ecdsa.PublicKey
		err    error
	)

	// Define the elliptic curve to be P-256
	ec = elliptic.P256()
	// Load the public key
	pubKey, err = cryptospecials.EccPubKeyLoad(pathPub)
	if err != nil {
		return false, err
	}

	/*
	* Parse VRF Proof string "[hex], [hex], [hex], [hex]"
	*    (1) Split comma seperated input string
	*    (2) Remove whitespace from resulting strings
	*	 (3) Decode the hex string into bytes
	*	 (4) Set the big.Int bytes as hex bytes
	 */
	splitString := strings.Split(proofString, ",")
	if Verbose {
		fmt.Println("SplitString: ", splitString)
	}
	swap, _ = hex.DecodeString(strings.Replace(splitString[0], " ", "", -1))
	eccVrf.EccProof.X.SetBytes(swap)
	swap, _ = hex.DecodeString(strings.Replace(splitString[1], " ", "", -1))
	eccVrf.EccProof.Y.SetBytes(swap)
	swap, _ = hex.DecodeString(strings.Replace(splitString[2], " ", "", -1))
	eccVrf.EccProof.C.SetBytes(swap)
	swap, _ = hex.DecodeString(strings.Replace(splitString[3], " ", "", -1))
	eccVrf.EccProof.S.SetBytes(swap)

	eccVrf.Beta, _ = hex.DecodeString(betaString)

	valid, err = eccVrf.Verify(sha256.New(), pubKey, ec, []byte(alphaString), eccVrf.Beta, &eccVrf.EccProof, Verbose)
	if err != nil {
		return false, err
	}

	return valid, nil
}
