package commands

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

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

// Check all of the required flags for the encrypt and decrypt commands to run successfully
func encPreChecks(cmd *cobra.Command, args []string) error {

	err := stdChecks(0, 5, cmd, args)
	if err != nil {
		return err
	}

	return nil
}

// Check all of the required flags for rsa command to run successfully
func rsaPreChecks(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("Error: Unknown arguments: %v", args)
	}
	// Check to make sure the appropriate flags are set
	if stdOutBool == false && len(outputPath) == 0 {
		return errors.New("Error: Must specify an output method")
	} else if len(inputPath) == 0 && rsaGen == false {
		return errors.New("Error: Must specify an input file")
	} else if rsaGen == true && sizeRSA == 0 {
		return errors.New("Error: Must specify a key size")
	}

	// Check to make sure the appropriate flags are set
	if stdOutBool == false && len(outputPath) == 0 {
		return errors.New("Error: Must specify an output method")
	}

	// RSA will not take StdIn as source input
	if len(stdInString) > 0 {
		return errors.New("Error: Reading from StdIn not available for RSA")
	}

	return nil
}

func vrfPreChecks(cmd *cobra.Command, args []string) error {

	return nil
}
