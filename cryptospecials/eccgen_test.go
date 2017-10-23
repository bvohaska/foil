package cryptospecials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"
)

func TestEccGenSaveLoad(t *testing.T) {

	var (
		privKey     *ecdsa.PrivateKey
		loadPrivKey *ecdsa.PrivateKey
		loadPubKey  *ecdsa.PublicKey
		ec          elliptic.Curve
		err         error
	)

	ec = elliptic.P256()

	privKey, err = EccPrivKeyGen(ec)
	if err != nil {
		t.Errorf("FAIL - %v", err)
	}

	err = EccKeySave(privKey, "ecPriv.pem", "ecPub.pem")
	if err != nil {
		t.Errorf("FAIL - EccKeySave - %v", err)
	}

	loadPrivKey, err = EccPrivKeyLoad("ecPriv.pem")
	if err != nil {
		t.Errorf("FAIL - EccPrivKeyLoad - %v", err)
	}

	loadPubKey, err = EccPubKeyLoad("ecPub.pem")
	if err != nil {
		t.Errorf("FAIL - EccPubKeyLoad - %v", err)
	}

	_, _ = loadPrivKey, loadPubKey
}
