package commands

import (
	"github.com/spf13/cobra"
)

func init() {
	// List of all top-level flags used in Foil
	FoilCmd.PersistentFlags().StringVarP(&keyString, "key", "k", "", "Use [hex] as the KEY for AES-GCM")
	FoilCmd.PersistentFlags().StringVarP(&passwordString, "password", "p", "", "Use [string] (--> PBKDF2) as  KEY for AES-GCM")
	FoilCmd.PersistentFlags().StringVarP(&inputPath, "in", "", "", "Read input as file from PATH=[string]")
	FoilCmd.PersistentFlags().StringVarP(&outputPath, "out", "", "", "Save output as file located at PATH=[string]")
	FoilCmd.PersistentFlags().StringVarP(&stdInString, "txtin", "", "", "Read input from StdIn as \"[string]\"")
	FoilCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Display verbose output")
	FoilCmd.PersistentFlags().BoolVarP(&stdOutBool, "txtout", "", false, "Display output on StdOut")

	// Add commands
	FoilCmd.AddCommand(versionCmd)
	FoilCmd.AddCommand(authorCmd)

	FoilCmd.AddCommand(encryptCmd)
	FoilCmd.AddCommand(decryptCmd)
}

// FoilCmd is an exportable function
var (
	stdInBool      bool
	stdOutBool     bool
	Verbose        bool
	inputPath      string
	keyString      string
	outputPath     string
	passwordString string
	stdInString    string

	FoilCmd = &cobra.Command{
		Use:   "foil",
		Short: "foil is CLI crypto tool with many functions.",
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
