package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {

}

var (
	oprfCmd = &cobra.Command{
		Use:   "oprf",
		Short: "Perform an ECC-ORF action",
		Long:  `Foil can perform [send] and [recv] operations for it's internal ECC-OPERF based on: https://eprint.iacr.org/2017/111.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a temporary placeholder")
		},
	}
)
