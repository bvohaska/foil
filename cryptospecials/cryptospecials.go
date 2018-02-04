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
	blank = new(big.Int)
	zero  = new(big.Int).SetInt64(int64(0))
	one   = new(big.Int).SetInt64(int64(1))
)

//ECPoint is an exportable struct
type ECPoint struct {
	X *big.Int
	Y *big.Int
}

// Hash2curve is an exportable function
/*
*  Warning: Try & Increment is not a constant-time algorithm
*  Warning: This function requres cryptographic vetting!
*  hash2curve implements the Try & Increment method for hashing into an Elliptic
*  Curve. Note: hash2curve only works on weierstrass curves at this point
*  Curve Type:
*		(1) Weierstrass - NIST Curves
*		(2) Others - Not currently supported
 */
func Hash2curve(data []byte, h hash.Hash, ec *elliptic.CurveParams, curveType int, verbose bool) (pt ECPoint, err error) {

	var (
		xByte   []byte
		counter int
	)
	pt.X = new(big.Int)
	pt.Y = new(big.Int)

	// Perform an initial hash of the data and save as an integer
	h.Write(data)
	xByte = h.Sum(nil)
	pt.X.SetBytes(xByte)
	pt.X.Mod(pt.X, ec.P)

	if curveType == 1 {
		/*
		* Determine (x^3 -3x + b)^(1/2) as defined by the weierstrass Elliptic Curve.
		* We use Jacobi symbols to determine if x is a quadratic residue in F_p. The
		* loop goes until a quadratic reside is found and could potentially go for a
		* very long time.
		* Parts taken from:
		*    https://golang.org/src/crypto/elliptic/elliptic.go?s=2054:2109#L55
		 */

		x3 := new(big.Int)
		threeX := new(big.Int)

		for {

			x3.Mul(pt.X, pt.X)
			x3.Mul(x3, pt.X)

			threeX.Lsh(pt.X, 1)
			threeX.Add(threeX, pt.X)

			x3.Sub(x3, threeX)
			x3.Add(x3, ec.B)
			x3.Mod(x3, ec.P) // x^3 -3x + b

			if big.Jacobi(x3, ec.Params().P) == 1 {
				break
			}

			pt.X.Add(pt.X, one)
			counter++
		}
		//  ModSqrt does not account for degenerate roots
		pt.Y.ModSqrt(x3, ec.P)

	} else {
		return ECPoint{}, fmt.Errorf("Error: Unsupported curve type. Currently support only Weierstrass curves")
	}

	if verbose {
		fmt.Printf("******\n\nHash2Curve\n\n******")
		fmt.Println("Length of xByte:", len(xByte))
		fmt.Println("P:", ec.P)
		fmt.Println("N:", ec.N)
		fmt.Println("B:", ec.B)

		fmt.Printf("Number of Try & Increment iterations: %d\n", counter)
		fmt.Println("x-xoordinate           :", pt.X)
		fmt.Println("y-coordinate           :", pt.Y)
		fmt.Println("x-coordinate bit length:", pt.X.BitLen())
		fmt.Println("y-coordinate bit length:", pt.Y.BitLen())
	}

	// Double check that the point (x,y) is on the provided elliptic curve
	if ec.IsOnCurve(pt.X, pt.Y) != true {
		return ECPoint{}, fmt.Errorf("Error: Unable to hash data onto curve! Point (x,y) not on given elliptic curve")
	}

	return pt, nil
}

/*
*  hashThree is an internal function that performs the H_3 hash.
*  zi is the collection of hash inputs as bytes,
*    zi = {g, h, PK, lambda, u, v}
*	    = {gx, gy, hx, hy, PKx, PKy, lambdax, lambday, ux, uy}
 */
func hashThree(h3 hash.Hash, z ...[]byte) (digest []byte) {

	for _, zi := range z {
		h3.Write(zi)
	}

	return h3.Sum(nil)
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
