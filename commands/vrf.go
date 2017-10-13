package commands

import (
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
	// Add local flags
	vrfGenCmd.LocalFlags().BoolVarP(&typePriv, "priv", "", false, "Specify input is a private key")
	vrfVerCmd.LocalFlags().BoolVarP(&typePub, "pub", "", false, "Specify input is a pub key")

	// Add VRF generate and verify as sub commands of vrf
	vrfCmd.AddCommand(vrfGenCmd)
	vrfCmd.AddCommand(vrfVerCmd)
}

var (
	typeRSA     bool
	typeECC     bool
	typePriv    bool
	typePub     bool
	alphaString string
	betaString  string
	proofString string
	alpha       []byte

	vrfCmd = &cobra.Command{
		Use:               "vrf",
		Short:             "Perform a VRF action",
		Long:              `Foil can perform RSA and ECC VRF operations defined in: https://eprint.iacr.org/2017/099.pdf.`,
		PersistentPreRunE: vrfPreChecks,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},
	}

	vrfGenCmd = &cobra.Command{
		Use:   "gen [TYPE] [PRIV PEM]",
		Short: "Generate a VRF proof and data",
		Long:  `Generate a VRF proof and data; [TYPE] is ECC or RSA.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},
	}
	vrfVerCmd = &cobra.Command{
		Use:   "verify [TYPE] [PUB PEM]",
		Short: "Verify an RSA-VRF proof and data",
		Long:  `Verify a VRF proof and data; [TYPE] is ECC or RSA.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},
	}
)

func doVRF() error {

	return nil
}
func genRsaVrf() error {

	var (
		vrfData cryptospecials.RSAVRF
	)

	// Load an RSA private key from file
	privKey, err := cryptospecials.RSAPrivKeyLoad(&inputPath, Verbose)
	if err != nil {
		return err
	}
	vrfData.PrivateKey = privKey

	alpha = []byte(alphaString)
	vrfData.Proof, vrfData.Beta, err = vrfData.Generate(alpha, Verbose)
	if err != nil {
		return err
	}

	// There is currently no standard for VRF output. Printin raw hex to StdIn in the meantime
	fmt.Printf("VRF Proof (hex): %x\n", vrfData.Proof)
	fmt.Printf("VRF Beta - H(Proof) (hex): %x\n", vrfData.Beta)

	return nil
}

func verRsaVrf() error {

	var (
		validVRF bool
		vrfData  cryptospecials.RSAVRF
	)

	alpha = []byte(alphaString)
	vrfData.Proof = []byte(proofString)
	// Load an RSA public key from file
	pubKey, err := cryptospecials.RSAPubKeyLoad(&inputPath, Verbose)
	if err != nil {
		return err
	}
	vrfData.PublicKey = *pubKey
	vrfData.Beta = []byte(betaString)

	validVRF, err = vrfData.Verify(alpha, &vrfData.PublicKey, Verbose)
	if err != nil {
		return err
	}

	// There is currently no standard for VRF output. Printin raw hex to StdIn in the meantime
	if validVRF {
		fmt.Printf("VRF Proof & Beta are valid")
	} else {
		fmt.Printf("VRF Proof & Beta are NOT valid")
	}

	return nil
}
