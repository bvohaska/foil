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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

type RSAVRF struct {
	proof []byte
	beta  []byte
	*rsa.PrivateKey
}

type OPRF struct {
}

func hash2curve() {

}

// RSAKeyGen is an exportable function
func RSAKeyGen(keySize int) (rsaPrivKey *rsa.PrivateKey, err error) {

	if keySize < 2048 {
		return nil, errors.New("Error: RSA key size less than 2048 bits")
	} else if keySize != 2048 && keySize != 3072 && keySize != 4096 {
		return nil, errors.New("Error: RSA key size is non-standard")
	}

	rng := rand.Reader
	privateKey, err := rsa.GenerateKey(rng, keySize)

	return privateKey, err
}

/*
*  This function has NOT been tested for cryptographic soundness at this point.
*  Do not use for cryptographic applications.
 */
func (vrf RSAVRF) generate(alpha []byte, verbose bool) ([]byte, []byte) {

	var (
		modLength int
		proof     big.Int
		outInt    big.Int
		beta      []byte
	)

	/*
	*  ModLength is the BYTE length of the modulus N.  output should be
	*  byte_length(RSA_Modulus) - 1. The "minus 1" is EXTREMLY important.
	*  If output is set to the length of N then the result of mgf1XOR could
	*  be bigger than N which in tern will cause issues with RSA verification.
	 */
	modLength = ((vrf.N.BitLen() + 8) / 8) - 1
	output := make([]byte, modLength-1)
	hash := sha256.New()

	mgf1XOR(output, hash, alpha)

	/*
	*  Warning: SetBytes interprets Bytes as Big-endian!
	*  Exponentiate = Proof (pi) = MGF1(alpha)^D (mod N)
	 */
	outInt.SetBytes(output)
	proof.Exp(&outInt, vrf.D, vrf.N)

	hash.Reset()
	beta = hash.Sum(proof.Bytes()) //Outputs in big-endian

	if verbose {
		fmt.Printf("****VRF.generate - Verbose Output****\n")

		fmt.Println("RSA Pub Mod - N (big Int):", vrf.N)
		fmt.Println("RSA Pub Exp - E (int):", vrf.E)
		fmt.Println("SECRET - RSA Priv Exp - D (big Int):", vrf.D)

		fmt.Printf("Alpha (string): %s\n", alpha)
		fmt.Printf("Alpha (hex): %x\n", alpha)

		fmt.Println("Proof (big Int):", proof)
		fmt.Printf("Proof (hex): %x\n", proof.Bytes())
		fmt.Printf("H(proof) (hex): %x\n", hash.Sum(nil))
		fmt.Printf("Beta = H(proof) (hex): %x\n", beta)

		fmt.Printf("Length of MGF1 output (Should be < len(N)): %d", len(output))
		fmt.Printf("MGF1 Output (hex): %x\n", output)
		fmt.Println("MGF1 Output as big.Int:", outInt)
	}

	return proof.Bytes(), beta

}

func (vrf RSAVRF) verify(mgf1Alpha []byte, pubKey *rsa.PublicKey, verbose bool) bool {

	var (
		betaCheck []byte
		intCheck  big.Int
		mgf1Check big.Int
	)

	hash := sha256.New()
	betaCheck = hash.Sum(vrf.proof)

	/*
	*  Generate: mgf1Check = (MGF1(alpha)^d)^e
	*  Eventually, want to check: mgf1Check ?= MGF1(alpha)
	 */
	e := big.NewInt(int64(pubKey.E))
	intCheck.SetBytes(vrf.proof)
	mgf1Check.Exp(&intCheck, e, pubKey.N)

	if verbose {
		fmt.Printf("****VRF.verify - Verbose Output****\n")

		fmt.Println("RSA Pub Mod - N (big Int):", pubKey.N)
		fmt.Println("RSA Pub Exp - E (int)", e)

		fmt.Println("vrf.proof (big Int)", intCheck)
		fmt.Printf("H(vrf.proof) - should be equal to Beta (hex): %x\n", betaCheck)
		fmt.Printf("Beta (hex): %x\n", vrf.beta)

		fmt.Printf("MGF1(Alpha) (hex): %x\n", mgf1Alpha)
		fmt.Println("MGF1Check (Big Int):", mgf1Check)
		fmt.Printf("MGF1Check (hex): %x\n", mgf1Check.Bytes())
	}

	// Check: compare the bytes of betaCheck = H(vrf.proof) ?= beta
	if bytes.Compare(betaCheck, vrf.beta) != 0 {
		if verbose {
			fmt.Println("FAIL - Could not verify: Beta == H(proof)")
		}
		return false
	}

	//Check: compare the bytes of (mgf1Check == trial_MGF1(alpha)) ?= (mgf1Alpha = MGF1(alpha))
	if bytes.Compare(mgf1Check.Bytes(), mgf1Alpha) != 0 {
		if verbose {
			fmt.Println("FAIL - Could not verify: trial_MGF1(alpha) == MGF1(alpha)")
		}
		return false
	}

	return true
}

/*
*  Taken from Golang source:
* https://golang.org/src/crypto/rsa/rsa.go?s=11736:11844#L308
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
*   Taken from Golang source:
*  https://golang.org/src/crypto/rsa/rsa.go?s=11736:11844#L323
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

func (rep OPRF) recv() {

}

func (rep OPRF) send() {

}
