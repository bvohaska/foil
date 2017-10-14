package cryptospecials

import (
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestHash2Curve(t *testing.T) {

	var (
		x *big.Int
		y *big.Int
	)

	//data := []byte("I'm a string!")
	data := []byte("I'm a string!")
	hash256 := sha256.New()
	ec := elliptic.P256()

	x, y, err := Hash2curve(data, hash256, ec.Params(), 1, false)
	if err != nil {
		t.Errorf("FAIL: %v\n", err)
	}
	if x == zero || y == zero {
		t.Errorf("FAIL: Zero values returned as points\n")
	}
}

/*
*  This test does not garantee the cryptogrpahic viability of rsaVRF.generate() or ecc OPRF
*  instead it checks the consistancy of the Mask, Salt, and Unmaks logic with EACH OTHER.
*  Further testing and validation of the cryptography is required.append
 */
