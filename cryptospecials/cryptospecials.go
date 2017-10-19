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
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"
)

// big.Int representation of Zero & One
var (
	zero = big.NewInt(int64(0))
	one  = big.NewInt(int64(1))
)

//Proof is an exportable struct
// ECC VRF proof struct
type Proof struct {
	x *big.Int
	y *big.Int
	c *big.Int
	s *big.Int
}

//ECCVRF is an exportable struct
type ECCVRF struct {
	EccProof Proof
	Alpha    []byte
	Beta     []byte
	elliptic.Curve
}

//Generate is an exportable method
/*
* From 'Making NSEC5 Practical for DNSSEC'
*  Pub: q, g, G, E, f
*   x (mod q), k (mod q)
*	G = E => f = 1
*	g = generator of order q
*  SK_vrf = rand(x)
*  PK_vrf = g^x => x*(gx, gy)
*  H_1 = hashing into elliptic curve, ec
*	lambda = Hash2Curve(alpha)^x = h^x
*	c = SHA2(g,h, PK, lambda, g^k, h^k) as Int
*	s = k-cx
*  Proof = (lambda, c, s)
*  Beta = H_2(lambda^f) : f = 1
 */
func (rep ECCVRF) Generate(alpha []byte, h hash.Hash, ec elliptic.Curve, verbose bool) (eccProof Proof, beta []byte, err error) {

	/*
	*	***** Special Note: H_2 & H_3 are the same in this implementation *****
	*   ***** Special Note: G = E which implies f = 1 in this implementation *****
	 */

	var (
		x, k, s, c *big.Int
		xPub, yPub *big.Int
		xh1, yh1   *big.Int
		xh2, yh2   *big.Int
		xgk, ygk   *big.Int
		xhk, yhk   *big.Int
	)

	// Set big.Ints to zero
	x, k, s, c = new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	xPub, yPub = new(big.Int), new(big.Int)
	xh1, yh1 = new(big.Int), new(big.Int)
	xh2, yh2 = new(big.Int), new(big.Int)
	xgk, ygk = new(big.Int), new(big.Int)
	xhk, yhk = new(big.Int), new(big.Int)

	// Randomly select a secret key: x
	x, err = rand.Int(rand.Reader, ec.Params().N)
	if err != nil {
		return Proof{}, nil, err
	}

	// Generate public key: x * (xG, yG) => g^x
	xPub, yPub = ec.ScalarMult(ec.Params().Gx, ec.Params().Gy, x.Bytes())

	// *** Step (1) ***
	// Hash VRF input alpha into the elliptic curve => h1 = (xh1, yh1) (Try & Increment below)
	xh1, yh1, err = Hash2curve(alpha, h, ec.Params(), 1, verbose)
	if err != nil {
		return Proof{}, nil, err
	}
	// Mask hx => x * h1 = x * (xh1, yh1)
	xh2, yh2 = ec.ScalarMult(xh1, yh1, x.Bytes())

	// *** Step (2) ***
	// Randomly select k
	k, err = rand.Int(rand.Reader, ec.Params().N)
	if err != nil {
		return Proof{}, nil, err
	}
	// Unwritten step: determine g^k and h^k
	// g^k = k * g = k * (xG, yG)
	xgk, ygk = ec.ScalarMult(ec.Params().Gx, ec.Params().Gy, k.Bytes())
	// lambda = h^k = k * h = k * (xh1, yh1)
	xhk, yhk = ec.ScalarMult(xh1, yh1, k.Bytes())

	// *** Step (3) *** (Most of this can be rearranged to save memory; doing for ease of analysis)
	// Compute c = H_3(g, h, g^x, h^x, g^k, h^k)
	// This is where H_3 is first used. Note this implmentation uses H_2 = H_3
	h.Reset()
	// g = (xG, yG)
	h.Write(ec.Params().Gx.Bytes())
	h.Write(ec.Params().Gy.Bytes())
	// h = (xh1, yh1)
	h.Write(xh1.Bytes())
	h.Write(yh1.Bytes())
	// g^x = (xPub, yPub)
	h.Write(xPub.Bytes())
	h.Write(yPub.Bytes())
	// h^x = (xh2, yh2)
	h.Write(xh2.Bytes())
	h.Write(yh2.Bytes())
	// g^k = (xgk, ygk)
	h.Write(xgk.Bytes())
	h.Write(ygk.Bytes())
	// h^k = (xhk, yhk)
	h.Write(xhk.Bytes())
	h.Write(yhk.Bytes())
	// Assign hash to c as integer
	c.SetBytes(h.Sum(nil))
	c.Mod(c, ec.Params().N)

	// *** Step (4) ****
	// Determine: s = k - c*x (mod q)
	s.Mul(c, x)
	s.Sub(k, s)
	s.Mod(s, ec.Params().N)

	// *** Generate proof Beta & VRF output Pi
	// Determine: Pi = (lambda, c, s) = ((xh1, yh1), c, s) ; Will be returned as (xh1, yh1, c, s) *big.Int
	eccProof.x, eccProof.y, eccProof.c, eccProof.s = xh1, yh1, c, s
	// Determine Beta = H_2(lambda^f) ; f = 1 in this implementation; H_2 = H_3 in this implementation
	h.Reset()
	// f = 1 => lambda^f = 1 * lambda = (xh1, yh1)
	h.Write(xh1.Bytes())
	h.Write(yh1.Bytes())
	beta = h.Sum(nil)

	if verbose {

		fmt.Printf("SECRET - x      : %v\n", x)
		fmt.Printf("SECRET - k      : %v\n", k)

		fmt.Printf("Public - s      : %v\n", s)
		fmt.Printf("Public - c      : %v\n", c)
		fmt.Printf("Public - h^x - x: %v\n", xh1)
		fmt.Printf("Public - h^x - y: %v\n", yh1)
	}

	return eccProof, beta, nil
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
		fmt.Println("N:", eCurve.N)
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
		fmt.Println("x-xoordinate           :", x)
		fmt.Println("y-coordinate           :", y)
		fmt.Println("x-coordinate bit length:", x.BitLen())
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
