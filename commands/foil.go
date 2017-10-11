package commands

import (
	"errors"

	"github.com/spf13/cobra"
)

func init() {
	// List of all top-level flags used in Foil
	FoilCmd.PersistentFlags().StringVarP(&keyString, "key", "k", "", "Use [hex] as the KEY for AES-GCM")
	FoilCmd.PersistentFlags().StringVarP(&passwordString, "password", "p", "", "Use [string] (--> PBKDF2) as  KEY for AES-GCM")
	FoilCmd.PersistentFlags().StringVarP(&inputPath, "in", "i", "", "Read input as file from PATH=[string]")
	FoilCmd.PersistentFlags().StringVarP(&outputPath, "out", "o", "", "Save output as file located at PATH=[string]")
	FoilCmd.PersistentFlags().StringVarP(&stdInString, "textin", "", "", "Read input from StdIn as \"[string]\"")
	FoilCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Display verbose output")
	FoilCmd.PersistentFlags().BoolVarP(&stdOutBool, "textout", "", false, "Display output on StdOut")

	// Add static  commands
	FoilCmd.AddCommand(versionCmd)
	FoilCmd.AddCommand(authorCmd)

	// Add dynamic commands
	FoilCmd.AddCommand(encryptCmd)
	FoilCmd.AddCommand(decryptCmd)
}

// FoilCmd is an exportable function
var (
	Verbose        bool
	stdOutBool     bool
	inputPath      string
	keyString      string
	outputPath     string
	passwordString string
	stdInString    string

	FoilCmd = &cobra.Command{
		Use:   "foil",
		Short: "foil is CLI crypto-playground with many features.",
		Long: `
Foil is a CLI crypto-playground. It was lovingly built to test out new and exciting cryptograpic mechanisms 
for those without too much cryptographic background. Foil attempts to minimize the number of paths toward using 
its crypto in a *bad* way.`,
		PersistentPreRunE: preChecks,
	}
)

//Execute is an exportable function
func Execute() {
	FoilCmd.Execute()
}

// Check all of the required flags for foil to run
func preChecks(cmd *cobra.Command, args []string) error {

	err := stdChecks(0, 7, cmd, args)
	if err != nil {
		return err
	}

	return nil
}

/*
* Check flag logic for proper:
*	(1) Input sources
*	(2) Output destinations
*	(3) Mutual exclusion
*	(4) Required flags
 */
func stdChecks(min int, max int, cmd *cobra.Command, args []string) error {

	// Check for the correct number of arguments
	if len(args) < min {
		return errors.New("Error: Too few arguments; Must specify direction for input & output")
	} else if len(args) > max {
		return errors.New("Error: Too many arguments")
	}

	// Check to make sure mutually exlusive flags are not set
	if len(stdInString) > 0 && len(inputPath) > 0 {
		return errors.New("Error: Too many sources for input; select only one")
	} else if len(outputPath) > 0 && stdOutBool {
		return errors.New("Error: Too many directions for output; select only one")
	} else if len(passwordString) > 0 && len(keyString) > 0 {
		return errors.New("Error: Too many directions for keys; select only one")
	}

	// Check to make sure the appropriate flags are set
	if stdOutBool == false && len(outputPath) == 0 {
		return errors.New("Error: Must specify an output method")
	} else if len(stdInString) == 0 && len(inputPath) == 0 {
		return errors.New("Error: Must specify an input method")
	}

	// If success, return nil
	return nil
}
