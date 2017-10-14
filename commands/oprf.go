package commands

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"foil/cryptospecials"
	"hash"
	"math/big"

	"github.com/spf13/cobra"
)

func init() {

	oprfCmd.PersistentFlags().BoolVarP(&mask, "mask", "", false, "mask a string using the ECC-OPRF")
	oprfCmd.PersistentFlags().BoolVarP(&salt, "salt", "", false, "salt a masked value using the ECC-OPRF")
	oprfCmd.PersistentFlags().BoolVarP(&unmask, "unmask", "", false, "unmask a salted value using the ECC-OPRF")
	oprfCmd.PersistentFlags().StringVarP(&oprfData, "indata", "", "", "use [string] as ECC-OPRF input (w_i)")
	//oprfCmd.PersistentFlags().BoolVarP(&curveP256, "p256", "", false, "use P-256 as the elliptic curve for ECC-OPRF")
	//oprfCmd.PersistentFlags().BoolVarP(&curveP384, "p384", "", false, "use P-384 as the elliptic curve for ECC-OPRF")
	//oprfCmd.PersistentFlags().BoolVarP(&curveP521, "p521", "", false, "use P-521 as the elliptic curve for ECC-OPRF")
	//oprfCmd.PersistentFlags().BoolVarP(&curve25519, "c25519", "", false, "use Curve25519 as the elliptic curve for ECC-OPRF")
	oprfCmd.PersistentFlags().StringVarP(&xString, "x", "", "", "use [hex] as x-coordinate for ECC-OPRF operation (mask, salt, unmask)")
	oprfCmd.PersistentFlags().StringVarP(&yString, "y", "", "", "use [hex] as y-coordinate for ECC-OPRF operation (mask, salt, unmask)")
	oprfCmd.PersistentFlags().StringVarP(&saltString, "s", "", "", "use [hex] as the secret value \"s\" for ECC-OPRF salting operation")
	oprfCmd.PersistentFlags().StringVarP(&rInvString, "rinv", "", "", "use [hex] as the secret value \"r_inv\" for ECC-OPRF unmaksing operation")
}

var (
	mask       bool
	salt       bool
	unmask     bool
	oprfData   string
	xString    string
	yString    string
	saltString string
	rInvString string

	oprfCmd = &cobra.Command{
		Use:   "oprf",
		Short: "Perform an ECC-ORF action",
		Long: "Foil can perform [mask], [salt], and [unmask] operations for it's internal" +
			" ECC-OPERF based on: https://eprint.iacr.org/2017/111.",
		PersistentPreRunE: oprfPreCheck,
		RunE:              doOprf,
	}
)

func oprfPreCheck(cmd *cobra.Command, args []string) error {

	// Ensure an OPRF operation is specified
	if mask == false && salt == false && unmask == false {
		return errors.New("Error: specify an OPRF operation")
	}
	// Ensure only one options is selected
	if (mask && salt) || (mask && unmask) || (salt && unmask) {
		return errors.New("Error: specify only one OPRF operation")
	}
	// Ensure initial OPRF input is provided
	if mask == true && oprfData == "" {
		return errors.New("Error: specify OPRF input")
	}
	// If salting or unmasking, ensure an elliptic curve point (x,y) is provided
	if salt == true || unmask == true {
		// Ensure that a masked or salted elliptic curve point is provided
		if xString == "" || yString == "" {
			return errors.New("Error: specify an elliptic curve point -x [hex] -y [hex]")
		}
		// If not secret salt value is provided, warn the suer that one will be generated
		if salt == true {
			if saltString == "" {
				fmt.Println("Warning: No salt value given; generating a random salt")
			}
			// Ensure that an r_inv value is provided
		} else if unmask == true {
			if rInvString == "" {
				return errors.New("Error: specify an r_inv [hex] for unmasking")
			}
		}
	}

	return nil
}

/*
* doOprf currently only supports P256 but minor changes can be made to support P384 and P521
 */
func doOprf(cmd *cobra.Command, args []string) error {

	var (
		x, y           *big.Int
		rInv, s, sOut  *big.Int
		xBytes, yBytes []byte
		err            error
		elem           cryptospecials.OPRF
		ec             elliptic.Curve
		h              hash.Hash
	)

	// Fill (x,y) with zero values
	x = new(big.Int)
	y = new(big.Int)
	// Parameters that need to be abstracted away if supporting more curves
	ec = elliptic.P256()
	h = sha256.New()

	// Decode StdIn(x,y) from [hex] into [bytes]; Check to ensure (x,y) is on the curve
	if !mask {
		xBytes, err = hex.DecodeString(xString)
		if err != nil {
			return err
		}
		yBytes, err = hex.DecodeString(yString)
		if err != nil {
			return err
		}
		x.SetBytes(xBytes)
		y.SetBytes(yBytes)
		if !ec.IsOnCurve(x, y) {
			return errors.New("Error: provided points not on elliptic curve")
		}
	}

	// Perform OPRF operations
	if mask {
		x, y, rInv, err = elem.Mask(oprfData, h, ec, Verbose)
		if err != nil {
			return err
		}

		fmt.Printf("Masked x-coordinate (hex): %x\n", x)
		fmt.Printf("Masked y-coordinate (hex): %x\n", y)
		fmt.Printf("SECRET - r inverse  (hex): %x\n", rInv)

	} else if salt {
		x, y, sOut, err = elem.Salt(x, y, s, ec, Verbose)
		if err != nil {
			return err
		}
		// Check to determine if s == sOut
		if s.Sub(s, sOut) != new(big.Int).SetUint64(uint64(0)) {
			fmt.Printf("SECRET - new s generated (hex): %x\n", sOut)
			fmt.Printf("SECRET - s given (hex)        : %x\n", s)
		}

		fmt.Printf("Salted x-coordinate (hex): %x\n", x)
		fmt.Printf("Salted y-coordinate (hex): %x\n", y)

	} else if unmask {
		// This does not check to ensure that rInv < N and warn the user if true
		x, y, err = elem.Unmask(x, y, rInv, ec, Verbose)
		if err != nil {
			return err
		}

		fmt.Printf("Unmasked x-coordinate (hex): %x\n", x)
		fmt.Printf("Unmasked y-coordinate (hex): %x\n", y)
	}

	return nil
}
