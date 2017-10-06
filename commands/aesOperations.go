package commands

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {

	// Define flags used by Encrypt/Decrypt and sub commands.
	// Use [cmd].Flags() for local commands
	encryptCmd.PersistentFlags().StringVarP(&adataString, "adata", "", "", "Use [string] as ADATA for AES-GCM")
	decryptCmd.PersistentFlags().StringVarP(&adataString, "adata", "", "", "Use [string] as ADATA for AES-GCM")
}

var (
	adataString string

	encryptCmd = &cobra.Command{
		Use:   "enc",
		Short: "Encrypt input with AES-256-GCM",
		Long:  ``,
		/*Args:  func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("requires at least one arg")
			}
			fmt.Println(*cmd)
			// Perform standard checks
			fmt.Println(args)
			err := stdChecks(1, 5, cmd, args)
			if err != nil {
				return err
			}
			if len(passwordString) == 0 && len(keyString) == 0 {
				fmt.Println("Warning: No key specified; A randomly generated key will be used") // Ensure that the key string is printed; previously handled by cliKeyLogic
			}
			// Perform encryptCmd specific checks
			return nil
		},*/
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Version 0.1a")
		},
	}

	decryptCmd = &cobra.Command{
		Use:   "dec",
		Short: "Decrypt input with AES-256-GCM",
		Long:  ``,
		/*Args: func(cmd *cobra.Command, args []string) error {
			// Perform standard checks
			err := stdChecks(3, 5, cmd, args)
			if err != nil {
				return err
			}
			if len(passwordString) == 0 && len(keyString) == 0 {
				return errors.New("Error: No key specified")
			}
			// Perform encryptCmd specific checks
			return nil
		},*/
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Version 0.1a")
		},
	}
)

// Check flag logic for ENC and DEC commands
func stdChecks(min int, max int, cmd *cobra.Command, args []string) error {
	// Check for the correct number of arguments
	if len(args) < min {
		return errors.New("Error: Too few arguments; Must specify direction for input & output")
	} else if len(args) > max {
		return errors.New("Error: Too many arguments")
	}
	// Check to make sure mutually exlusive flags are not set
	if stdInBool && len(inputPath) > 0 {
		return errors.New("Error: Too many sources for input; select only one")
	} else if len(outputPath) > 0 && stdOutBool {
		return errors.New("Error: Too many directions for output; select only one")
	} else if len(passwordString) > 0 && len(keyString) > 0 {
		return errors.New("Error: Too many directions for keys; select only one")
	}
	// Check to make sure the appropriate flags are set
	if stdOutBool == false && len(outputPath) == 0 {
		return errors.New("Error: Must specify an output path")
	} else if stdInBool == false && len(inputPath) == 0 {
		return errors.New("Error: Must specify an input path")
	}
	return nil
}
