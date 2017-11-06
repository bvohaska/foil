package commands

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"foil/cryptospecials"
	"hash"
	"math/big"
	"testing"
)

/*
	// Foil variables
	Verbose        bool
	stdOutBool     bool
	inputPath      string
	keyString      string
	outputPath     string
	stdInString    string

	// OPRF variables
	mask       bool
	salt       bool
	unmask     bool
	oprfData   string
	xString    string
	yString    string
	saltString string
	rInvString string

*/

func TestOprf(t *testing.T) {

	var (
		x, y, xm, ym   *big.Int
		xs, ys, xu, yu *big.Int
		rInv, s, sOut  *big.Int
		zero           *big.Int
		xBytes, yBytes []byte
		err            error
		elem           cryptospecials.OPRF
		ec             elliptic.Curve
		h              hash.Hash
	)

	zero = new(big.Int).SetUint64(uint64(0))
	// Set Verbose to false
	Verbose = false
	// Test points; Fill all (x_i,y_i) with zero values
	xm, ym = new(big.Int), new(big.Int)
	xs, ys, xu, yu = new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	// Parameters that need to be abstracted away if supporting more curves
	ec = elliptic.P256()
	h = sha256.New()
	stdInString = "LegitTest"

	//mask = true
	// ****************************Perform masking operation*******************************
	xm, ym, rInv, err = elem.Mask(stdInString, h, ec, Verbose)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	if !ec.IsOnCurve(xm, ym) {
		fmt.Printf("Masked x-coordinate (hex): %x\n", xm)
		fmt.Printf("Masked y-coordinate (hex): %x\n", ym)
		fmt.Printf("SECRET - r inverse  (hex): %x\n", rInv)
		fmt.Printf("SECRET - r          (hex): %x\n", rInv.ModInverse(rInv, ec.Params().N))
		t.Errorf("FAIL - Error: provided points not on elliptic curve")
	}

	// *********************Test reading and decoding (x,y) from CLI************************
	xString = hex.EncodeToString(xm.Bytes())
	yString = hex.EncodeToString(ym.Bytes())
	// Decode StdIn(x,y) from [hex] into [bytes]; Check to ensure (x,y) is on the curve
	xBytes, err = hex.DecodeString(xString)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	yBytes, err = hex.DecodeString(yString)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	x = new(big.Int)
	y = new(big.Int)
	x.SetBytes(xBytes)
	y.SetBytes(yBytes)
	if !ec.IsOnCurve(x, y) {
		t.Errorf("FAIL - Error: provided points not on elliptic curve")
	}
	if x.Sub(x, xm) == zero && y.Sub(y, ym) == zero {
		t.Errorf("FAIL - Error: CLI mask (x,y) not matching with calculated mask (xm, ym)")
	}

	//salt = true
	// **********************************Perform salting OPRF operations*********************
	// Test s generation
	s = nil
	xs, ys, sOut, err = elem.Salt(xm, ym, s, ec, Verbose)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	s = new(big.Int)
	xs, ys, sOut, err = elem.Salt(xm, ym, s, ec, Verbose)
	if err != nil {
		fmt.Println("sOut :", sOut)
		fmt.Println("s    :", s)
		t.Errorf("FAIL - %v", err)
	}
	// Generate random s and provide to OPRF.salt
	s = new(big.Int)
	s, err = rand.Int(rand.Reader, ec.Params().N)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	xs, ys, sOut, err = elem.Salt(xm, ym, s, ec, Verbose)

	//unmask = true
	// ********************************Perform unmasking OPRF operations*********************
	// This does not check to ensure that rInv < N and warn the user if true
	xu, yu, err = elem.Unmask(xs, ys, rInv, ec, Verbose)
	if err != nil {
		fmt.Printf("Unmasked x-coordinate (hex): %x\n", xu)
		fmt.Printf("Unmasked y-coordinate (hex): %x\n", yu)
		t.Errorf("FAIL - %v", err)
	}

	//May want to export OPRF.unsalt to ensure OPRF correctness

}
