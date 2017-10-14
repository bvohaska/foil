package cryptospecials

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

func TestOPRFComplete(t *testing.T) {

	var (
		x, y                  *big.Int
		xMask, yMask, rInv    *big.Int
		xSalt, ySalt, s, sOut *big.Int
		xUnmask, yUnmask      *big.Int
		xUnsalt, yUnsalt      *big.Int
		xCheck, yCheck        *big.Int
		verbose               bool
		dataString            string
		hData                 []byte
		rep                   OPRF
		err                   error
	)

	verbose = true
	dataString = "I'm a string!"
	hash256 := sha256.New()
	ec := elliptic.P256()
	s = new(big.Int)
	s, err = rand.Int(rand.Reader, ec.Params().N)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}
	s.Mod(s, ec.Params().N)

	xMask, yMask, rInv, err = rep.Mask(dataString, hash256, ec, verbose)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	xSalt, ySalt, sOut, err = rep.Salt(xMask, yMask, s, ec, verbose)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	xUnmask, yUnmask, err = rep.Unmask(xSalt, ySalt, rInv, ec, verbose)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	xUnsalt, yUnsalt, err = rep.unsalt(xUnmask, yUnmask, s, ec, verbose)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	// Check for OPRF reversability if s & r are known
	xCheck, yCheck, err = rep.Unmask(xMask, yMask, rInv, ec, verbose)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	hash256.Reset()
	_, err = hash256.Write([]byte(dataString))
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}
	hData = hash256.Sum(nil)
	hash256.Reset()
	x, y, err = Hash2curve(hData, hash256, ec.Params(), 1, verbose)

	trialXZero, trialYZero := zero, zero
	if trialXZero.Sub(xCheck, x) != zero || trialYZero.Sub(yCheck, y) != zero {
		fmt.Println("x      :", x)
		fmt.Println("xCheck :", xCheck)
		fmt.Println("xUnsalt:", xUnsalt)
		fmt.Println("y      :", y)
		fmt.Println("yCheck :", yCheck)
		fmt.Println("yUnsalt:", yUnsalt)
		fmt.Println("s:", s)
		fmt.Println("sOut:", sOut)
		t.Errorf("FAIL - Check points do not match")
	}

	if true {
		//t.Errorf("No Error")
	}

}
