

package cryptospecials

import(
	"fmt"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

type RSAVRF struct {

}

type OPRF struct {

}

func RSAKeyGen(keySize int) (rsaPrivKey *rsa.PrivateKey, err error) {

	if keySize < 2048 {
		return nil, errors.New("Error: RSA key size less than 2048 bits")
	}else if (keySize != 2048 || keySize !=3072 || keySize != 4096) {
		fmt.Println("Warning: RSA key size is non-standard")
	}

	rng := rand.Reader
	privateKey, err := rsa.GenerateKey(rng, keySize)

	return privateKey, err
}

func (rsa RSAVRF) generate() {

}

func (rsa RSAVRF) verify() {

}

func (rep OPRF) hash2curve() {

}

func (rep OPRF) recv() {

}

func (rep OPRF) send() {

}