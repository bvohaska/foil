# Cryptospecials Package

ECDSA key generation

## Components in `eccgen.go`

The following fuinctions, structures, or variables are available,

### Available Variables

None

### Available Structures

None

### Available Functions

* `EccPrivKeyGen` - Generates a random elliptic curve secret and public key for an elliptic curve

* `EccKeySave` - Saves the private and public key as an ECDSA PEM file

* `EccPrivKeyLoad` - Load a private key from an ECDSA private PEM file

* `EccPubKeyLoad` - Load a public key from an ECDSA public PEM file

## Function Descriptions

### `EccPrivKeyGen(ec elliptic.Curve) (privKey *ecdsa.PrivateKey, err error)`

* #### Input

  `ec` - an elliptic curve (typically P-256)

* #### Output

  `privKey` - an elliptic curve private key on the curve `ec`; the public key is contained within the PrivateKey structure

  `err` - a standard formatted error

### `EccKeySave(privKey *ecdsa.PrivateKey, savePriv string, savePub string) (err error)`

* #### Input

  `privKey` - an elliptic curve private key in ECDSA structure format

  `savePriv` - the file path where the private key will be saved

  `savePub` - the file path where the public key will be saved

* #### Output

  `err` - a standard formatted error

### `EccPrivKeyLoad(sourcePath string) (privKey *ecdsa.PrivateKey, err error)`

* #### Input

  `sourcePath` - the file path to the ECDSA private PEM file

* #### Output

  `privKey` - an elliptic curve private key in ECDSA structure format

  `err` - a standard formatted error

### `EccPubKeyLoad(sourcePath string) (pubKey *ecdsa.PublicKey, err error)`

* #### Input

  `sourcePath` - the file path to the ECDSA public PEM file

* #### Output

  `privKey` - an elliptic curve private key in ECDSA structure format

  `err` - a standard formatted error

## Examples

Example testing code,

```go

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

```

## Additional Details

None

## Contributors

Brian Vohaska