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
		dataString         string
		hData              []byte
		rInv, s, sOut      *big.Int
		pt                 ECPoint
		mask, salt, unmask ECPoint
		unsalt, check      ECPoint
		rep                OPRF
		verbose            bool
		err                error
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

	mask, rInv, err = rep.Mask(dataString, hash256, ec, verbose)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	salt, sOut, err = rep.Salt(mask, s, ec, verbose)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	unmask, err = rep.Unmask(salt, rInv, ec, verbose)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	unsalt, err = rep.unsalt(unmask, s, ec, verbose)
	if err != nil {
		t.Errorf("FAIL - Error: %v", err)
	}

	// Check for OPRF reversability if s & r are known
	check, err = rep.Unmask(mask, rInv, ec, verbose)
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
	pt, err = Hash2curve(hData, hash256, ec.Params(), 1, verbose)

	trialXZero, trialYZero := zero, zero
	if trialXZero.Sub(check.X, pt.X) != zero || trialYZero.Sub(check.Y, pt.Y) != zero {
		fmt.Println("x      :", pt.X)
		fmt.Println("xCheck :", check.X)
		fmt.Println("xUnsalt:", unsalt.X)
		fmt.Println("y      :", pt.Y)
		fmt.Println("yCheck :", check.Y)
		fmt.Println("yUnsalt:", unsalt.Y)
		fmt.Println("s:", s)
		fmt.Println("sOut:", sOut)
		t.Errorf("FAIL - Check points do not match")
	}

	if true {
		//t.Errorf("No Error")
	}
}
