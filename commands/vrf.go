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
	// Add local flags
	vrfGenCmd.LocalFlags().BoolVarP(&typePriv, "priv", "", false, "Specify input is a private key")
	vrfVerCmd.LocalFlags().BoolVarP(&typePub, "pub", "", false, "Specify input is a pub key")

	// Add VRF generate and verify as sub commands of vrf
	vrfCmd.AddCommand(vrfGenCmd)
	vrfCmd.AddCommand(vrfVerCmd)
}

var (
	typeRSA  bool
	typeECC  bool
	typePriv bool
	typePub  bool

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
		Use:   "gen [TYPE] [PRIV] [OUT]",
		Short: "Generate a VRF proof and data",
		Long:  `Generate a VRF proof and data; [TYPE] is ECC or RSA.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},
	}
	vrfVerCmd = &cobra.Command{
		Use:   "verify [TYPE] [PUB] [OUT]",
		Short: "Verify an RSA-VRF proof and data",
		Long:  `Verify a VRF proof and data; [TYPE] is ECC or RSA.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},
	}
)

func genVrf(source *string) error {

	var (
		vrfData cryptospecials.RSAVRF
	)
	privKey, err := cryptospecials.RSAPrivKeyLoad(source, Verbose)
	if err != nil {
		return err
	}
	vrfData.PrivateKey = privKey

	return nil
}

func verVrf() {

}
