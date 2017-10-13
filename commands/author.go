package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {

}

var (
	authorCmd = &cobra.Command{
		Use:   "authors",
		Short: "Display the list of Foil authors",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Authors: Brian Vohaska <bvohaska@gmail.com>")
		},
	}
)
