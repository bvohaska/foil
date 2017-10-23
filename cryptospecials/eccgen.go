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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

//EccPrivKeyGen is an exportable function
/*
*  EccPrivKeyGen uses the ecdsa package to neatly generate a random key 's' with
*  a public key s*(Gx, Gy). This is stored in a Private Key struct
 */
func EccPrivKeyGen(ec elliptic.Curve) (privKey *ecdsa.PrivateKey, err error) {

	privKey, err = ecdsa.GenerateKey(ec, rand.Reader)
	if err != nil {
		return nil, err
	}

	return privKey, nil

}

//EccKeySave is an exportable function
func EccKeySave(privKey *ecdsa.PrivateKey, savePriv string, savePub string) (err error) {

	var (
		keyBytes     []byte
		savePrivFile *os.File
		savePubFile  *os.File
	)

	// Attempt to open file at savePriv
	savePrivFile, err = os.Create(savePriv)
	if err != nil {
		return err
	}
	defer savePrivFile.Close()
	// Encode the private key as DER bytes
	keyBytes, err = x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}
	// Write the PEM to saveFile
	err = pem.Encode(savePrivFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	// Attempt to open file at savePub
	savePubFile, err = os.Create(savePub)
	if err != nil {
		return err
	}
	defer savePubFile.Close()
	// Encode the public key as DER bytes
	keyBytes, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return err
	}
	err = pem.Encode(savePubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})
	if err != nil {
		return err
	}

	return nil

}

//EccPrivKeyLoad is an exportable function
func EccPrivKeyLoad(sourcePath string) (privKey *ecdsa.PrivateKey, err error) {

	var (
		readFile []byte
		swap     *pem.Block
	)

	// Attempt to open ReadFile at sourcePath
	readFile, err = ioutil.ReadFile(sourcePath)
	if err != nil {
		return nil, err
	}
	swap, _ = pem.Decode(readFile)
	privKey, err = x509.ParseECPrivateKey(swap.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

//EccPubKeyLoad is an exportable function
func EccPubKeyLoad(sourcePath string) (pubKey *ecdsa.PublicKey, err error) {

	var (
		readFile []byte
		swap     *pem.Block
		ipubKey  interface{}
	)

	// Attempt to open ReadFile at sourcePath
	readFile, err = ioutil.ReadFile(sourcePath)
	if err != nil {
		return nil, err
	}
	swap, _ = pem.Decode(readFile)
	ipubKey, err = x509.ParsePKIXPublicKey(swap.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey = ipubKey.(*ecdsa.PublicKey)

	return pubKey, nil
}
