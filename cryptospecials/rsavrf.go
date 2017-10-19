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
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

//RSAVRF is an exportable struct
type RSAVRF struct {
	Proof []byte
	Alpha []byte
	Beta  []byte
	*rsa.PrivateKey
}

// Generate is an exportable method
/*
*  This function has NOT been tested for cryptographic soundness at this point.
*  Do not use for cryptographic applications until it has been properly vetted.
*  The RSA-VRF below is based on: https://eprint.iacr.org/2017/099.pdf. Alpha is
*  the VRF mutual reference string. NOTE: hashes use SHA-256 not SHA-1 for MGF1.
 */
func (vrf RSAVRF) Generate(alpha []byte, rsaPrivKey *rsa.PrivateKey, verbose bool) (proofBytes []byte, beta []byte, err error) {

	// Check that private key has values for N (big Int) and D (big Int) or return error
	if rsaPrivKey.N == zero || rsaPrivKey.D == zero {
		return nil, nil, errors.New("Error: No private key supplied")
	}

	var (
		modLength int
		proof     big.Int
		outInt    big.Int
	)

	/*
	*  ModLength is the BYTE length of the modulus N.  output should be
	*  byte_length(RSA_Modulus) - 1. The "minus 1" is EXTREMLY important.
	*  If output is set to the length of N then the result of mgf1XOR could
	*  be bigger than N which in tern will cause issues with RSA verification.
	 */
	modLength = ((rsaPrivKey.N.BitLen() + 8) / 8) - 1
	output := make([]byte, modLength-1)
	hash256 := sha256.New()

	mgf1XOR(output, hash256, alpha)

	/*
	*  Warning: SetBytes interprets Bytes as Big-endian!
	*  Exponentiate = Proof (pi) = MGF1(alpha)^D (mod N)
	*  D is an RSA Secret!
	 */
	outInt.SetBytes(output)
	proof.Exp(&outInt, rsaPrivKey.D, rsaPrivKey.N)

	hash256.Reset()
	hash256.Write(proof.Bytes())
	beta = hash256.Sum(nil) //Outputs in big-endian

	if verbose {
		fmt.Printf("****VRF.generate - Verbose Output****\n")

		fmt.Println("RSA Pub Mod - N (big Int):", rsaPrivKey.N)
		fmt.Println("RSA Pub Exp - E (int):", rsaPrivKey.E)
		fmt.Println("SECRET - RSA Priv Exp - D (big Int):", rsaPrivKey.D)

		fmt.Printf("Alpha (string): %s\n", alpha)
		fmt.Printf("Alpha (hex): %x\n", alpha)

		fmt.Println("Proof (big Int):", proof)
		fmt.Printf("Proof (hex): %x\n", proof.Bytes())
		fmt.Printf("H(proof) (hex): %x\n", hash256.Sum(nil))
		fmt.Printf("Beta = H(proof) (hex): %x\n", beta)

		fmt.Printf("Length of MGF1 output (Should be < len(N)): %d", len(output))
		fmt.Printf("MGF1 Output (hex): %x\n", output)
		fmt.Println("MGF1 Output as big.Int:", outInt)
	}

	return proof.Bytes(), beta, nil

}

// Verify is an exportable method
/*
*  This function has NOT been tested for cryptographic soundness at this point.
*  Do not use for cryptographic applications until it has been properly vetted.
*  The RSA-VRF below is based on: https://eprint.iacr.org/2017/099.pdf. Alpha is
*  the VRF mutual reference string. NOTE: hashes use SHA-256 not SHA-1 for MGF1.
 */
func (vrf RSAVRF) Verify(alpha []byte, beta []byte, proof []byte, pubKey *rsa.PublicKey, verbose bool) (validity bool, err error) {

	// Check that proof and beta have values or return error
	if proof == nil || beta == nil {
		return false, errors.New("Error: H(beta) or Beta not supplied")
	}
	// Check that the pub key has values for N (bit Int) and E (int) or return error
	if pubKey.N == zero || pubKey.E == 0 {
		return false, errors.New("Error: No public key not supplied")
	}

	var (
		modLength int
		betaCheck []byte
		mgf1Alpha []byte
		intCheck  big.Int
		mgf1Check big.Int
	)

	/*
	*  ModLength is the BYTE length of the modulus N.  output should be
	*  byte_length(RSA_Modulus) - 1. The "minus 1" is EXTREMLY important.
	*  If output is set to the length of N then the result of mgf1XOR could
	*  be bigger than N which in tern will cause issues with RSA verification.
	 */
	modLength = ((pubKey.N.BitLen() + 8) / 8) - 1
	mgf1Alpha = make([]byte, modLength-1)
	hash256 := sha256.New()
	mgf1XOR(mgf1Alpha, hash256, alpha)

	// Generate a test beta - H(proof)
	hash256.Reset()
	hash256.Write(proof)
	betaCheck = hash256.Sum(nil)

	/*
	*  Generate: mgf1Check = (MGF1(alpha)^d)^e
	*  Eventually, want to check: mgf1Check ?= MGF1(alpha)
	 */
	e := big.NewInt(int64(pubKey.E))
	intCheck.SetBytes(proof)
	mgf1Check.Exp(&intCheck, e, pubKey.N)

	if verbose {
		fmt.Printf("****VRF.verify - Verbose Output****\n")

		fmt.Println("RSA Pub Mod - N (big Int):", pubKey.N)
		fmt.Println("RSA Pub Exp - E (int)", e)

		fmt.Println("vrf.proof (big Int)", intCheck)
		fmt.Printf("H(vrf.proof) - should be equal to Beta (hex): %x\n", betaCheck)
		fmt.Printf("Beta (hex): %x\n", beta)

		fmt.Printf("MGF1(Alpha) (hex): %x\n", mgf1Alpha)
		fmt.Println("MGF1Check (Big Int):", mgf1Check)
		fmt.Printf("MGF1Check (hex): %x\n", mgf1Check.Bytes())
	}

	// Check: compare the bytes of betaCheck = H(vrf.proof) ?= beta
	if bytes.Compare(betaCheck, beta) != 0 {
		if verbose {
			fmt.Println("FAIL - Could not verify: Beta == H(proof)")
		}
		return false, nil
	}

	//Check: compare the bytes of (mgf1Check == trial_MGF1(alpha)) ?= (mgf1Alpha = MGF1(alpha))
	if bytes.Compare(mgf1Check.Bytes(), mgf1Alpha) != 0 {
		if verbose {
			fmt.Println("FAIL - Could not verify: trial_MGF1(alpha) == MGF1(alpha)")
		}
		return false, nil
	}

	return true, nil
}
