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
	"errors"
	"fmt"
	"hash"
	"math/big"
)

//OPRF is an exportable struct
type OPRF struct {
	RSecret    []byte
	RSecretInv []byte
	elliptic.Curve
}

//Mask is an exportable method
/*
*  OPRF.Send() represents EC-OPRF sec. 3.1 Steps (1) and (2) with hashing into an elliptic
*  curve via the try-and-increment method.
*  Sec. 3.1:
*	eq. (1) G_i = H(w_i)
*	eq. (2) M_i = m_i * G_i
 */
func (rep OPRF) Mask(data string, h hash.Hash, ec elliptic.Curve, verbose bool) (xMask *big.Int, yMask *big.Int, rInv *big.Int, err error) {

	var (
		x       *big.Int
		y       *big.Int
		r       *big.Int
		rByte   []byte
		hData   []byte
		numRead int
	)

	// Fill r, rInv with zeros (or Seg Fault when using r.SetBytes(...))
	r = new(big.Int)
	rInv = new(big.Int)

	// Read a random byte of size size(P) from OS random (usually dev/urandom)
	rng := rand.Reader
	rByte = make([]byte, (ec.Params().BitSize+8)/8-1)
	numRead, err = rng.Read(rByte)
	if err != nil {
		return nil, nil, nil, err
	}

	/*
	*  Hash the data using the cryptographic hash of choice. Reccomend using SHA-256.
	*  Attempt to map H(data) into the elliptic curve defined by ec.
	*  Currently only supporting weierstrass curves.
	 */
	_, err = h.Write([]byte(data))
	if err != nil {
		return nil, nil, nil, err
	}
	hData = h.Sum(nil)
	h.Reset()
	x, y, err = Hash2curve(hData, h, ec.Params(), 1, verbose)

	/*
	*  Determine r (mod N) and rInv (mod N) such that r*rInv = 1 (mod N). N
	*  is the order of elliptic curve subgroup.
	 */
	r.SetBytes(rByte)
	r.Mod(r, ec.Params().N)
	rInv.ModInverse(r, ec.Params().N)
	xMask, yMask = ec.ScalarMult(x, y, r.Bytes())
	if xMask == zero || yMask == zero {
		return nil, nil, nil, errors.New("Error: The resulting point r*H(data) = (x1, y1) contains zeros")
	}

	if verbose {
		fmt.Println("Number of random bytes read:", numRead)
		fmt.Println("Size of H(data)            :", len(hData))
		fmt.Println("SECRET x-coordinate:", x)
		fmt.Println("SECRET y-coordinate:", y)
		fmt.Println("SECRET r           :", r)
		fmt.Println("SECRET r-inv       :", rInv)
		fmt.Println("Masked x-coordinate:", xMask)
		fmt.Println("Masked y-coordinate:", yMask)
		fmt.Println("Is Masked (x,y) on the curve:", ec.IsOnCurve(xMask, yMask))
	}

	// (x1,y1) = r*(x,y) : x, y <-- H(data) into ec
	return xMask, yMask, rInv, nil
}

//Salt is an exportable method
/*
*  OPRF.Salt() represents EC-OPRF sec. 3.1 Step (3)
*  Sec. 3.1:
*	eq. (3) S_i = s_i * M_i = s * (xMask, yMask) = s * r * (x, y)
 */
func (rep OPRF) Salt(xMask *big.Int, yMask *big.Int, s *big.Int, ec elliptic.Curve, verbose bool) (xSalt *big.Int, ySalt *big.Int, sOut *big.Int, err error) {

	/*
	*  Ensure s is not zero; if so, generate a random number and return as error. Note:
	*  this does not check to ensure thas s (mod N) == s (as given). If s > s(mod N),
	*  results will not be as anticipated.
	 */
	if s == nil || s == zero {
		s = new(big.Int)
		randBytes := make([]byte, (ec.Params().BitSize+8)/8-1)
		rand.Reader.Read(randBytes)
		s.SetBytes(randBytes)
		s.Mod(s, ec.Params().N)
		fmt.Println("SECRET - s (new)  :", s)
	}

	xSalt, ySalt = ec.ScalarMult(xMask, yMask, s.Bytes())

	if verbose {
		fmt.Println("SECRET - s (used)  :", s)
		fmt.Println("Salted x-coordinate:", xSalt)
		fmt.Println("Salted y-coordinate:", ySalt)
		fmt.Println("Is Salted (x, y) on the curve:", ec.IsOnCurve(xSalt, ySalt))
	}

	return xSalt, ySalt, s, nil
}

//Unmask is an exportable method
/*
*  OPRF.Unmask() represents EC-OPRF sec. 3.1 Step (4)
Sec. 3.1:
*	eq. (4) U_i = r_inv * S_i = r_inv * s * (xMask, yMask) = r_inv * s * r * (x, y) = s * (x, y)
*/
func (rep OPRF) Unmask(xSalt *big.Int, ySalt *big.Int, rInv *big.Int, ec elliptic.Curve, verbose bool) (xUnmask *big.Int, yUnmask *big.Int, err error) {

	xUnmask, yUnmask = ec.ScalarMult(xSalt, ySalt, rInv.Bytes())

	if verbose {
		fmt.Println("Unmasked x-coordinate:", xUnmask)
		fmt.Println("Unmasked y-coordinate:", yUnmask)
		fmt.Println("Is Unmasked (x, y) on the curve:", ec.IsOnCurve(xUnmask, yUnmask))
	}
	return xUnmask, yUnmask, nil
}

/*
*  OPRF.unsalt is not exportable and is for testing only. This method will remove s from U_i
*  resulting in s_inv * s * U_i = s_inv * s * (x, y) = (x, y) = H(data). This operation is not
*  in the OPRF paper.
 */
func (rep OPRF) unsalt(xUnmask *big.Int, yUnmask *big.Int, s *big.Int, ec elliptic.Curve, verbose bool) (xUnsalt *big.Int, yUnsalt *big.Int, err error) {

	var (
		sInv *big.Int
	)

	// Calculated s_inv (mod N) such that s_inv * s = 1 (mod N)
	sInv = new(big.Int)
	sInv.ModInverse(s, ec.Params().N)

	xUnsalt, yUnsalt = ec.ScalarMult(xUnmask, yUnmask, sInv.Bytes())

	if verbose {
		fmt.Println("Is unsalted (x, y) on the curve:", ec.IsOnCurve(xUnsalt, yUnsalt))
	}

	return xUnsalt, yUnsalt, nil
}
