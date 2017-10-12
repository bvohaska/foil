package commands

import (
	"fmt"
	"foil/cryptospecials"

	"github.com/spf13/cobra"
)

func init() {

	// Add VRF specific flags

	// Add VRF generate and verify as sub commands of vrf
	vrfCmd.AddCommand(vrfGenCmd)
	vrfCmd.AddCommand(vrfVerCmd)
}

var (
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
		Use:   "gen [RSA-PRIV] [OUT]",
		Short: "Generate an RSA-VRF proof and data",
		Long:  `Generate an RSA-VRF proof and data; Foil can perform RSA and ECC VRF operations defined in: https://eprint.iacr.org/2017/099.pdf.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},
	}
	vrfVerCmd = &cobra.Command{
		Use:   "verify [RSA-PUB] [OUT]",
		Short: "Verify an RSA-VRF proof and data",
		Long:  `Verify an RSA-VRF proof and data; Foil can perform RSA and ECC VRF operations defined in: https://eprint.iacr.org/2017/099.pdf.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},
	}
)

func vrfPreChecks(cmd *cobra.Command, args []string) error {

	return nil
}

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
