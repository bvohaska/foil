package commands

import (
	"github.com/spf13/cobra"
)

func init() {
	// List of all top-level flags used in Foil

	FoilCmd.PersistentFlags().StringVarP(&inputPath, "in", "", "", "read input as file from PATH=[string]")
	FoilCmd.PersistentFlags().StringVarP(&outputPath, "out", "", "", "save output as file located at PATH=[string]")
	FoilCmd.PersistentFlags().StringVarP(&stdInString, "textin", "", "", "read input from StdIn as [string]")
	FoilCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "display verbose output")
	FoilCmd.PersistentFlags().BoolVarP(&stdOutBool, "textout", "", false, "display output on StdOut")

	// Add static  commands
	FoilCmd.AddCommand(versionCmd)
	FoilCmd.AddCommand(authorCmd)

	// Add dynamic commands
	FoilCmd.AddCommand(aesCmd)
	FoilCmd.AddCommand(rsaCmd)
	FoilCmd.AddCommand(ecCmd)
	FoilCmd.AddCommand(vrfCmd)
	FoilCmd.AddCommand(oprfCmd)

	// Suppress Cobra internal error reporting in favor of Foil errors
	FoilCmd.SilenceErrors = true
}

// FoilCmd is an exportable function
var (
	Verbose     bool
	stdOutBool  bool
	inputPath   string
	outputPath  string
	stdInString string

	FoilCmd = &cobra.Command{
		Use:   "foil",
		Short: "foil is CLI crypto-playground with many features.",
		Long: "Foil is a CLI crypto-playground. It was lovingly built to test out" +
			"\nnew and exciting cryptograpic mechanisms for those without too" +
			"\nmuch cryptographic background. Foil attempts to minimize the" +
			"\nnumber of ways one can use foil crypto in a \"bad\" way.",
	}
)

//Execute is an exportable function
func Execute() {
	FoilCmd.Execute()
}
