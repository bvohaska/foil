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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
)

//Proof is an exportable struct
// ECC VRF proof struct
type Proof struct {
	X *big.Int
	Y *big.Int
	C *big.Int
	S *big.Int
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
* Note: Generate currently treats H_2 & H_3 as the same function h (hash.Hash)
* Note: In this implementation: G = E => f = 1
*
* From 'Making NSEC5 Practical for DNSSEC':
*
*  Pub: q, g, G, E, f ; g = generator of order q
*  Secret: x , k : (mod q)
*
*  H_1 = hashing into an elliptic curve
*  c = H_3(g,h, PK, lambda, g^k, h^k) (mod q)
*  s = k - c*k (mod q)
*  Proof = (lambda, c, s)
*  Beta = H_2(lambda^f)
 */
func (rep ECCVRF) Generate(h hash.Hash, ec elliptic.Curve, privKey *ecdsa.PrivateKey, alpha []byte, verbose bool) (eccProof Proof, beta []byte, err error) {

	/*
	*  ***** Special Note: H_2 & H_3 are the same in this implementation *****
	*  ***** Special Note: G = E which implies f = 1 in this implementation *****
	*  Note: This method was written to be easily analyzed. Once it has been
	*  validated it will be optimized (removal of unneeded big.Int, new(), etc)
	 */

	var (
		k, s, c *big.Int
		pth1    ECPoint
		pth2    ECPoint
		ptgk    ECPoint
		pthk    ECPoint

		swap []byte
	)

	// Set big.Ints to zero
	k = new(big.Int)
	s, c = new(big.Int), new(big.Int)
	pth1.X, pth1.Y = new(big.Int), new(big.Int)
	pth2.X, pth2.Y = new(big.Int), new(big.Int)
	ptgk.X, ptgk.Y = new(big.Int), new(big.Int)
	pthk.X, pthk.Y = new(big.Int), new(big.Int)

	// *** Step (1) ***
	/*
	* Note: h1 currently uses the Try & Increment method for hashing into an elliptic curve
	*
	*  Determine: h, h^x
	*
	*		h 	= H_1(alpha)
	*			= Hash2Curve(...)
	*			= (xh1 , yh1)
	*
	*		h^x = x * h
	*			= x *(xh1, yh1)
	*		    = (xh2, yh2)
	 */
	pth1, err = Hash2curve(alpha, h, ec.Params(), 1, verbose)
	if err != nil {
		return Proof{}, nil, err
	}
	pth2.X, pth2.Y = ec.ScalarMult(pth1.X, pth1.Y, privKey.D.Bytes())
	eccProof.X = pth2.X
	eccProof.Y = pth2.Y

	// *** Step (2) ***
	// Randomly choose: k (mod 1)
	k, err = rand.Int(rand.Reader, ec.Params().N)
	if err != nil {
		return Proof{}, nil, err
	}
	k.Mod(k, ec.Params().N)

	// *** Step (2b) (implied) ***
	/*
	*  Determine: g^k, h^k
	*
	*  		g^k = k * g
	*			= k * (xG, yG)
	*			= (xgk, ygk)
	*
	*		h^k = k * h
	*			= k * (xh1, yh1)
	*			= (xhk, yhk)
	 */
	ptgk.X, ptgk.Y = ec.ScalarBaseMult(k.Bytes())
	pthk.X, pthk.Y = ec.ScalarMult(pth1.X, pth1.Y, k.Bytes())

	// *** Step (3) ***
	/*
	*  Note: H_3 is used here; this implmentation uses H_2 = H_3 but can be changed
	*
	*  Compute:
	*		c = H_3(g, h, g^x, h^x, g^k, h^k)
	*
	*  g = (xG, yG)
	*  h = (xh1, yh1)
	*  g^x = (privKey.X, privKey.Y)
	*  h^x = (xh2, yh2)
	*  g^k = (xgk, ygk)
	*  h^k = (xhk, yhk)
	 */
	h.Reset()
	swap = hashThree(h,
		ec.Params().Gx.Bytes(), ec.Params().Gy.Bytes(),
		pth1.X.Bytes(), pth1.Y.Bytes(),
		privKey.X.Bytes(), privKey.Y.Bytes(),
		pth2.X.Bytes(), pth2.Y.Bytes(),
		ptgk.X.Bytes(), ptgk.Y.Bytes(),
		pthk.X.Bytes(), pthk.Y.Bytes())
	c.SetBytes(swap)
	c.Mod(c, ec.Params().N)
	if verbose {
		fmt.Printf("c - Calulated (hex): %x\n", swap)
	}

	// *** Step (4) ****
	// Determine: s = k - c*x (mod q)
	s.Mul(c, privKey.D)
	s.Sub(k, s)
	s.Mod(s, ec.Params().N)

	// *** Final Step ***
	/*
	*  Note: Currently, E = G, H_2 = H_3 in this implementation
	*
	*  Generate: Beta (VRF Proof) & Pi (VRF Output)
	*  Determine:
	*		Pi	= (lambda, c, s)
	*			= ((xh1, yh1), c, s) ; returned as (xh1, yh1, c, s *big.Int)
	*
	*		Beta 	= H_2(lambda^f) ; E = G => f = 1
	*				= H_2(lambda)
	*				= H_2(xh1, xh2)
	 */
	eccProof.C = c
	eccProof.S = s
	h.Reset()
	h.Write(pth2.X.Bytes())
	h.Write(pth2.Y.Bytes())
	beta = h.Sum(nil)

	if verbose {

		fmt.Printf("SECRET - x      : %v\n", privKey.D)
		fmt.Printf("SECRET - k      : %v\n\n", k)

		fmt.Printf("Public - xGx    : %v\n", privKey.X)
		fmt.Printf("Public - xGy    : %v\n", privKey.Y)
		fmt.Printf("Public - s      : %v\n", s)
		fmt.Printf("Public - c      : %v\n", c)
		fmt.Printf("Public - h^x - x: %v\n", pth2.X)
		fmt.Printf("Public - h^x - y: %v\n", pth2.Y)
		fmt.Printf("Public - beta (hex): %x\n\n", beta)

		fmt.Println("c - Inputs:")
		fmt.Printf("  G - x     (hex): %x\n", ec.Params().Gx.Bytes())
		fmt.Printf("  G - y     (hex): %x\n", ec.Params().Gy.Bytes())
		fmt.Printf("  h1(a) - x (hex): %x\n", pth1.X.Bytes())
		fmt.Printf("  h1(a) - y (hex): %x\n", pth1.Y.Bytes())
		fmt.Printf("  PubK - x  (hex): %x\n", privKey.X.Bytes())
		fmt.Printf("  PubK - y  (hex): %x\n", privKey.Y.Bytes())
		fmt.Printf("  h2 - x    (hex): %x\n", pth2.X.Bytes())
		fmt.Printf("  h2 - y    (hex): %x\n", pth2.Y.Bytes())
		fmt.Printf("  g^k - x   (hex): %x\n", ptgk.X.Bytes())
		fmt.Printf("  g^k - y   (hex): %x\n", ptgk.Y.Bytes())
		fmt.Printf("  h^k - x   (hex): %x\n", pthk.X.Bytes())
		fmt.Printf("  h^k - y   (hex): %x\n\n", pthk.Y.Bytes())

	}

	return eccProof, beta, nil
}

//Verify is an exportable method
/*
* Warning: Verify currently treats H_2 & H_3 as the same function h (hash.Hash)
 */
func (rep ECCVRF) Verify(h hash.Hash, pubK *ecdsa.PublicKey, ec elliptic.Curve, alpha []byte, beta []byte, eccProof *Proof, verbose bool) (valid bool, err error) {

	var (
		swapByte       []byte
		h1, u, v, swap ECPoint
	)

	// Set big.Ints to zero

	// *** Step (1) ***
	/* Determine: u
	*
	*		u 	= (PubK)^c * G^s ; convert from group notation to elliptic curve, (^, *) --> (*, +)
	* 			= (c*x*G) + (s*G)
	*			= (c*x)*G + (k-c*x)*G
	*			= (c*x + k - c*x)*G
	*			= k*G = G^k
	 */
	u.X, u.Y = ec.ScalarMult(pubK.X, pubK.Y, eccProof.C.Bytes())
	swap.X, swap.Y = ec.ScalarBaseMult(eccProof.S.Bytes())
	u.X, u.Y = ec.Add(u.X, u.Y, swap.X, swap.Y)

	// *** Step (2) ***
	/*
	*  Check: lambda on elliptic curve
	*
	*		IsOnCurve(lambda) =? true
	*
	*  Determine: h, v
	*
	*		h = H_1(alpha) ; currently using Try & Increment
	*
	*		v	= (lambda^f)^c * (h)^s ; convert from group notation to elliptic curve, (^, *) --> (*, +)
	*			= (c*lambda) + (s*h) : E = G => f = 1
	*			= c*x*(h) + s*(h)
	*			= (c*x + s)*h
	*			= (c*x + k - c*x)*h
	*			= k*h = h^k
	 */
	// NOTE: This is only true of G = E
	if ec.IsOnCurve(eccProof.X, eccProof.Y) == false {
		return false, fmt.Errorf("Error: The lambda provided is not on the provided elliptic curve")
	}
	// Note: using sha256; this should be abstracted to other functions at some point
	h1, err = Hash2curve(alpha, sha256.New(), ec.Params(), 1, verbose)
	if err != nil {
		return false, err
	}
	v.X, v.Y = ec.ScalarMult(eccProof.X, eccProof.Y, eccProof.C.Bytes())
	swap.X, swap.Y = ec.ScalarMult(h1.X, h1.Y, eccProof.S.Bytes())
	v.X, v.Y = ec.Add(v.X, v.Y, swap.X, swap.Y)

	// *** Step (3) ***
	/*
	*  Note: H_3 is used here; this implmentation uses H_2 = H_3 but can be changed
	*
	*  Determine: c
	*
	*		c = H_3(g, h, g^x, h^x, g^k, h^k)
	*
	*  			g = (xG, yG)
	*			h = (xh1, yh1)
	*			g^x = (privKey.X, privKey.Y)
	*			h^x = (xh2, yh2)
	*			g^k = (xgk, ygk)
	*			h^k = (xhk, yhk)
	*
	*  Check: Proof.c is valid
	*
	*  		Proof.c ?= c ; Convert c to big.Int and subtract from Proof.c
	 */
	h.Reset()
	swapByte = hashThree(h,
		ec.Params().Gx.Bytes(), ec.Params().Gy.Bytes(),
		h1.X.Bytes(), h1.Y.Bytes(),
		pubK.X.Bytes(), pubK.Y.Bytes(),
		eccProof.X.Bytes(), eccProof.Y.Bytes(),
		u.X.Bytes(), u.Y.Bytes(),
		v.X.Bytes(), v.Y.Bytes(),
	)

	if verbose {

		fmt.Printf("Public - s      : %v\n", eccProof.S)
		fmt.Printf("Public - h^x - x: %v\n", eccProof.X)
		fmt.Printf("Public - h^x - y: %v\n", eccProof.Y)
		fmt.Println("PubK = (x, y)")
		fmt.Printf("  x             : %v\n", pubK.X)
		fmt.Printf("  y             : %v\n", pubK.Y)
		fmt.Println("u = (x, y)")
		fmt.Printf("  x             : %v\n", u.X)
		fmt.Printf("  y             : %v\n", u.Y)
		fmt.Println("v = (x, y)")
		fmt.Printf("  x             : %v\n", v.X)
		fmt.Printf("  y             : %v\n\n", v.Y)

		fmt.Printf("c - Provided   (hex): %x\n", eccProof.C.Bytes())
		fmt.Printf("c - Calculated (hex): %x\n", swapByte)
		fmt.Println("c - Calculated Inputs:")
		fmt.Printf("  G - x     (hex): %x\n", ec.Params().Gx.Bytes())
		fmt.Printf("  G - y     (hex): %x\n", ec.Params().Gy.Bytes())
		fmt.Printf("  h1(a) - x (hex): %x\n", h1.X.Bytes())
		fmt.Printf("  h1(a) - y (hex): %x\n", h1.Y.Bytes())
		fmt.Printf("  PubK - x  (hex): %x\n", pubK.X.Bytes())
		fmt.Printf("  PubK - y  (hex): %x\n", pubK.Y.Bytes())
		fmt.Printf("  h2 - x    (hex): %x\n", eccProof.X.Bytes())
		fmt.Printf("  h2 - y    (hex): %x\n", eccProof.Y.Bytes())
		fmt.Printf("  u - x     (hex): %x\n", u.X.Bytes())
		fmt.Printf("  u - y     (hex): %x\n", u.Y.Bytes())
		fmt.Printf("  v - x     (hex): %x\n", v.X.Bytes())
		fmt.Printf("  v - y     (hex): %x\n\n", v.Y.Bytes())

	}

	// Validate Proof.c = Calculated c
	if bytes.Compare(eccProof.C.Bytes(), swapByte) != 0 {
		return false, nil
	}

	// *** Final Step ***
	/*
	*  Determine: beta
	*
	*		beta = H_2(lambda^f)
	*			 = H_2(lambda) : E = G => f = 1
	*			 = H_2(lambdax, lambday)
	*
	*	Check: beta = Proof.beta
	*
	*		beta ?= Proof.beta ; bytes.Compare(beta, Proof.beta)
	 */
	h.Reset()
	h.Write(eccProof.X.Bytes())
	h.Write(eccProof.Y.Bytes())
	swapByte = h.Sum(nil)
	if verbose {
		fmt.Printf("Beta - Calculated (hex): %x\n", swapByte)
		fmt.Printf("Beta - Provided   (hex): %x\n\n", beta)
	}
	if bytes.Compare(beta, swapByte) != 0 {
		return false, fmt.Errorf("Validation Error: Beta - provided_beta does not equal calculated_beta")
	}

	return true, nil
}
