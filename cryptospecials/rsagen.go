/*
*	This package contains mechanisms that will allow for VRF and OPRF calculations.
*
*	OPRF: https://eprint.iacr.org/2017/111
*
*	RSA-VRF: https://eprint.iacr.org/2017/099.pdf
*
*		-Brian
 */

/*
 *	RSA generation, load, and save functions are defined here
 */

package cryptospecials

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// RSAKeyGen is an exportable function
/*
*  RSAKeyGen allows only 2048, 3072, and 4096 bit key sizes (NITS standards). For larger
*  key sizes use the ecc else it is likely that performance will be an issue. It is
*  also much easier to utilize constant-time algorithms with ecc than useing rsa algos.
 */
func RSAKeyGen(keySize int) (*rsa.PrivateKey, error) {

	if keySize < 2048 {
		return nil, errors.New("Error: RSA key size less than 2048 bits")
	} else if keySize != 2048 && keySize != 3072 && keySize != 4096 {
		return nil, errors.New("Error: RSA key size is non-standard")
	}

	rng := rand.Reader
	privateKey, err := rsa.GenerateKey(rng, keySize)

	return privateKey, err
}

// RSAKeySave is an exportable function
/*
*  RSAKeySave saves a public or private RSA key from a private RSA key. Files
*  are saved as PEM.
 */
func RSAKeySave(privKey *rsa.PrivateKey, savePubKey bool, printStdIn bool, dest *string, verbose bool) error {

	var (
		derBytes []byte
		pemBytes []byte
		err      error
	)

	/*
	*  Choose if saving a public or private key.
	*  Encode the private key into a DER then a PEM
	 */
	if savePubKey {
		derBytes, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		if err != nil {
			return fmt.Errorf("Error: %v", err)
		}
		pemBytes = pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: derBytes,
			},
		)
		if verbose {
			fmt.Printf("Der Bytes (hex): %x\n", derBytes)
			fmt.Println("Pem Bytes:", pemBytes)
		}
	} else {
		derBytes = x509.MarshalPKCS1PrivateKey(privKey)
		pemBytes = pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: derBytes,
			},
		)
		if verbose {
			fmt.Println("SECRET - Der Bytes:", derBytes)
			fmt.Println("SECRET - Pem Bytes:", pemBytes)
		}
	}

	// This logic allows the RSA key to be printed to stdin & saved to file
	if *dest == "" && printStdIn == false {
		fmt.Println("No destination provided. Saving file as: ./IAMArsaKey.pem")
		*dest = "IAMArsaKey.pem"
	} else if *dest == "" && printStdIn == true {
		fmt.Println(pemBytes)
	}
	// Write the PEM to file
	if len(*dest) > 0 {
		err = ioutil.WriteFile(*dest, pemBytes, 0644)
		if err != nil {
			return fmt.Errorf("Error: %v", err)
		}
	}

	return nil
}

// RSAPrivKeyLoad is an exportable function
func RSAPrivKeyLoad(source *string, verbose bool) (*rsa.PrivateKey, error) {

	var (
		rawPem  []byte
		err     error
		privKey *rsa.PrivateKey
	)

	// Read raw PEM file
	rawPem, err = ioutil.ReadFile(*source)
	if err != nil {
		return privKey, fmt.Errorf("Error: %v", err)
	}
	// Decode raw PEM into private key
	pemData, _ := pem.Decode(rawPem)
	if pemData == nil {
		return privKey, errors.New("Error: Unable to parse PEM file - it may be empty or not in PEM format")
	}
	privKey, err = x509.ParsePKCS1PrivateKey(pemData.Bytes)
	if err != nil {
		return privKey, fmt.Errorf("Error: %v", err)
	}
	if verbose {
		fmt.Println("SECRET - rawPem:", rawPem)
		fmt.Println("SECRET - pemData:", pemData)
		fmt.Println("SECRET - privKey:", privKey)
	}
	return privKey, nil
}

// RSAPubKeyLoad is an exportable function
func RSAPubKeyLoad(source *string, verbose bool) (*rsa.PublicKey, error) {
	var (
		rawPem []byte
		err    error
	)

	// Read raw PEM file
	rawPem, err = ioutil.ReadFile(*source)
	if err != nil {
		return nil, fmt.Errorf("Error: %v", err)
	}
	// Decode raw PEM into private key
	pemData, _ := pem.Decode(rawPem)
	if pemData == nil {
		return nil, errors.New("Error: Unable to parse PEM file - it may be empty or not in PEM format")
	}
	pubKey, err := x509.ParsePKIXPublicKey(pemData.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error: %v", err)
	}
	if verbose {
		fmt.Println("rawPem:", rawPem)
		fmt.Println("pemData:", pemData)
		fmt.Println("pubKey:", pubKey)
	}
	// Extract the pub key and ensure it is of type RSA
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		return pubKey, nil
	default:
		return nil, errors.New("Key type is not RSA")
	}
}
