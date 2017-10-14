/*
*	This package contains mechanisms that will allow for VRF and OPRF calculations.
*
*	OPRF: https://eprint.iacr.org/2017/111
*
*	RSA-VRF: https://eprint.iacr.org/2017/099.pdf
*
*		-Brian
 */

package cryptospecials

import (
	"crypto/elliptic"
	"fmt"
	"hash"
	"math/big"
)

// big.Int representation of Zero & One
var (
	zero = big.NewInt(int64(0))
	one  = big.NewInt(int64(1))
)

//ECCVRF is an exportable struct
type ECCVRF struct {
	Proof []byte
	Beta  []byte
	elliptic.Curve
}

func (rep ECCVRF) Generate() {

}

func (rep ECCVRF) Verify() {

}

// Hash2curve is an exportable function
/*
*  Warning: Try & Increment is not a constant-time algorithm
*  Warning: This function requres cryptographic vetting!
*  hash2curve implements the Try & Increment method for hashing into an Elliptic
*  Curve. Note: hash2curve only works on weierstrass curves at this point
 */
func Hash2curve(data []byte, h hash.Hash, eCurve *elliptic.CurveParams, curveType int, verbose bool) (x *big.Int, y *big.Int, err error) {

	/*
	*  Curve Type:
	*		(1) Weierstrass - NIST Curves
	*		(2) Others - Not currently supported
	 */

	var (
		xByte   []byte
		counter int
	)

	x = big.NewInt(0)
	y = big.NewInt(0)
	one := new(big.Int).SetInt64(int64(1))
	h.Write(data)
	xByte = h.Sum(nil)
	x.SetBytes(xByte)
	x.Mod(x, eCurve.P)

	if verbose {
		fmt.Println("Length of xByte:", len(xByte))
		fmt.Println("P:", eCurve.P)
		fmt.Println("B:", eCurve.B)
	}

	if curveType == 1 {
		/*
		* Determine (x^3 -3x + b)^(1/2) as defined by the weierstrass Elliptic Curve. Parts taken from:
		*    https://golang.org/src/crypto/elliptic/elliptic.go?s=2054:2109#L55
		 */

		x3 := big.NewInt(0)
		threeX := big.NewInt(0)
		for {

			x3.Mul(x, x)
			x3.Mul(x3, x)

			threeX.Lsh(x, 1)
			threeX.Add(threeX, x)

			x3.Sub(x3, threeX)
			x3.Add(x3, eCurve.B)
			x3.Mod(x3, eCurve.P) // x^3 -3x + b
			//fmt.Println("x3:", x3)

			// Use Jacobi symbols to determine if x is a quadratic residue in F_p
			if big.Jacobi(x3, eCurve.Params().P) == 1 {
				break
			}

			x.Add(x, one)
			counter++
		}
		/*
		*  ModSqrt does not account for degenerate roots
		 */
		y.ModSqrt(x3, eCurve.P)

	} else {
		return nil, nil, fmt.Errorf("Error: Unsupported curve type. Currently support only Weierstrass curves")
	}

	// Double check that the point (x,y) is on the provided elliptic curve
	if eCurve.IsOnCurve(x, y) != true {
		return nil, nil, fmt.Errorf("Error: Unable to hash data onto curve! Point (x,y) not on given elliptic curve")
	}

	if verbose {
		fmt.Printf("Number of Try & Increment iterations: %d\n", counter)
		fmt.Println("x-xoordinate:", x)
		fmt.Println("x-coordinate bit length:", x.BitLen())
		fmt.Println("y-coordinate:", y)
		fmt.Println("y-coordinate bit length:", y.BitLen())
	}

	return x, y, nil
}

/*
* Taken from Golang source:
*   https://golang.org/src/crypto/rsa/rsa.go?s=11736:11844#L308
* incCounter increments a four byte, big-endian counter.
 */
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}

	c[0]++
}

/*
*  Taken from Golang source:
*    https://golang.org/src/crypto/rsa/rsa.go?s=11736:11844#L323
*  mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
*  specified in PKCS#1 v2.1.
 */
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {

	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}
