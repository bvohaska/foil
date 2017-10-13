package commands

import (
	"github.com/spf13/cobra"
)

func init() {
	// List of all top-level flags used in Foil

	FoilCmd.PersistentFlags().StringVarP(&inputPath, "in", "", "", "Read input as file from PATH=[string]")
	FoilCmd.PersistentFlags().StringVarP(&outputPath, "out", "", "", "Save output as file located at PATH=[string]")
	FoilCmd.PersistentFlags().StringVarP(&stdInString, "textin", "", "", "Read input from StdIn as [string]")
	FoilCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Display verbose output")
	FoilCmd.PersistentFlags().BoolVarP(&stdOutBool, "textout", "", false, "Display output on StdOut")

	// Add static  commands
	FoilCmd.AddCommand(versionCmd)
	FoilCmd.AddCommand(authorCmd)

	// Add dynamic commands
	FoilCmd.AddCommand(aesCmd)
	FoilCmd.AddCommand(rsaCmd)
	FoilCmd.AddCommand(vrfCmd)
	//FoilCmd.AddCommand(oprfCmd)

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
		Long: `
Foil is a CLI crypto-playground. It was lovingly built to test out new and exciting cryptograpic mechanisms 
for those without too much cryptographic background. Foil attempts to minimize the number of paths toward using 
its crypto in a *bad* way.`,
	}
)

//Execute is an exportable function
func Execute() {
	FoilCmd.Execute()
}
