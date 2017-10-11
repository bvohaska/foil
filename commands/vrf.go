package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {

}

var (
	vrfCmd = &cobra.Command{
		Use:   "vrf",
		Short: "Perform a VRF action",
		Long:  `Foil can perform RSA and ECC VRF operations defined in: https://eprint.iacr.org/2017/099.pdf.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},
	}
)
