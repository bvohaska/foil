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

// Test I/O on doOPRF
func TestDoOPRF(t *testing.T) {

	// Test prechecks

	// Go through state space
}

// Test core functions of the OPRF
func TestCoreOprf(t *testing.T) {

	var (
		xBytes, yBytes    []byte
		rInv, s, sOut     *big.Int
		zero              *big.Int
		pt, ptm, pts, ptu cryptospecials.ECPoint
		elem              cryptospecials.OPRF
		ec                elliptic.Curve
		h                 hash.Hash
		err               error
	)

	zero = new(big.Int).SetUint64(uint64(0))
	// Set Verbose to false
	Verbose = false
	// Test points; Fill all (x_i,y_i) with zero values
	ptm.X, ptm.Y = new(big.Int), new(big.Int)
	pts.X, pts.Y, ptu.X, ptu.Y = new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	// Parameters that need to be abstracted away if supporting more curves
	ec = elliptic.P256()
	h = sha256.New()
	stdInString = "LegitTest"

	//mask = true
	// ****************************Perform masking operation*******************************
	ptm, rInv, err = elem.Mask(stdInString, h, ec, Verbose)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	if !ec.IsOnCurve(ptm.X, ptm.Y) {
		fmt.Printf("Masked x-coordinate (hex): %x\n", ptm.X)
		fmt.Printf("Masked y-coordinate (hex): %x\n", ptm.Y)
		fmt.Printf("SECRET - r inverse  (hex): %x\n", rInv)
		fmt.Printf("SECRET - r          (hex): %x\n", rInv.ModInverse(rInv, ec.Params().N))
		t.Errorf("FAIL - Error: provided points not on elliptic curve")
	}

	// *********************Test reading and decoding (x,y) from CLI************************
	xString = hex.EncodeToString(ptm.X.Bytes())
	yString = hex.EncodeToString(ptm.Y.Bytes())
	// Decode StdIn(x,y) from [hex] into [bytes]; Check to ensure (x,y) is on the curve
	xBytes, err = hex.DecodeString(xString)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	yBytes, err = hex.DecodeString(yString)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	pt.X = new(big.Int)
	pt.Y = new(big.Int)
	pt.X.SetBytes(xBytes)
	pt.Y.SetBytes(yBytes)
	if !ec.IsOnCurve(pt.X, pt.Y) {
		t.Errorf("FAIL - Error: provided points not on elliptic curve")
	}
	if pt.X.Sub(pt.X, ptm.X) == zero && pt.Y.Sub(pt.Y, ptm.Y) == zero {
		t.Errorf("FAIL - Error: CLI mask (x,y) not matching with calculated mask (xm, ym)")
	}

	//salt = true
	// **********************************Perform salting OPRF operations*********************
	// Test s generation
	s = nil
	pts, sOut, err = elem.Salt(ptm, s, ec, Verbose)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}
	s = new(big.Int)
	pts, sOut, err = elem.Salt(ptm, s, ec, Verbose)
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
	pts, sOut, err = elem.Salt(ptm, s, ec, Verbose)

	//unmask = true
	// ********************************Perform unmasking OPRF operations*********************
	// This does not check to ensure that rInv < N and warn the user if true
	ptu, err = elem.Unmask(pts, rInv, ec, Verbose)
	if err != nil {
		fmt.Printf("Unmasked x-coordinate (hex): %x\n", ptu.X)
		fmt.Printf("Unmasked y-coordinate (hex): %x\n", ptu.Y)
		t.Errorf("FAIL - %v", err)
	}
	//May want to export OPRF.unsalt to ensure OPRF correctness

}
