# Cryptospecials Package

RSA key generation

## Components in `rsagen.go`

The following fuinctions, structures, or variables are available,

### Available Variables

None

### Available Structures

None

### Available Functions

* `RSAKeyGen`

* `RSAKeySave`

* `RSAPrivKeyLoad`

* `RSAPubKeyLoad`

## Function Descriptions

### `RSAKeyGen(keySize int) (privKey *rsa.PrivateKey, err error)`

* #### Input

  `keysize` - an integer from {2048, 3072, 4096} specifying the size fo the RSA modulus

* #### Output

  `privKey` - an RSA private key; the public key is contained within the PrivateKey structure

  `err` - a standard formatted error

### `RSAKeySave(privKey *rsa.PrivateKey, savePubKey bool, printStdIn bool, dest *string, verbose bool) (err error)`

* #### Input

  `privKey` - an RSA private key; the public key is contained within the PrivateKey structure

  `savePubKey` - indicates that a public key will be extracted from a private PEM provided by the user

  `printStdIn` - specify whether or not the key information will be printed to StdIn

  `dest` - the file path where the private or public key will be saved

  `verbose` - specify verbose output

* #### Output

  `err` - a standard formatted error

### `RSAPrivKeyLoad(source *string, verbose bool) (privKey *rsa.PrivateKey, err error)`

* #### Input

  `source` - the file path to the RSA public PEM file

  `verbose` - specify verbose output

* #### Output

  `privKey` - an RSA private key; the public key is contained within the PrivateKey structure

  `err` - a standard formatted error

### `RSAPubKeyLoad(source *string, verbose bool) (*rsa.PublicKey, error)`

* #### Input

  `source` - the file path to the RSA public PEM file

  `verbose` - specify verbose output

* #### Output

  `*rsa.PublicKey` - an RSA public key structure

  `error` - a standard formatted error

## Examples

Example `RSAKeyGen` testing code,

```go

func TestRSAKeyGen(t *testing.T) {

  var (
    testKey *rsa.PrivateKey
    err     error
  )

  testKey, err = RSAKeyGen(1024)
  if err == nil {
    t.Errorf("FAIL - Short key size test failed")
  }

  testKey, err = RSAKeyGen(2049)
  if err == nil {
    t.Errorf("FAIL - No warning to user concerning non-standard key sizes")
  }

  testKey, err = RSAKeyGen(2048)
  if err != nil {
    t.Errorf("FAIL - Fail on normal operation - %v", err)
  }

  if testKey.Primes[0].ProbablyPrime(64) == false || testKey.Primes[1].ProbablyPrime(64) == false {
    t.Errorf("FAIL - RSA modulus is divisible by non-primes")
  }
}

```

Example `RSAKeySave` testing code,

```go

func TestRSAKeySave(t *testing.T) {

  // Test saving a RSA private key
  dest := "IAMAPrivKeyTest.pem"
  privKey, err := RSAKeyGen(2048)
  err = RSAKeySave(privKey, false, false, &dest, false)
  if err != nil {
    t.Errorf("FAIL - %v\n", err)
  }

  // Test saving a RSA public key
  dest = "IAMAPubKeyTest.pem"
  err = RSAKeySave(privKey, true, false, &dest, true)
  if err != nil {
    t.Errorf("FAIL - %v\n", err)
  }
}

```

Example `RSAKeySave` testing code,

```go

func TestRSAKeyLoad(t *testing.T) {

  // Test saving a RSA private key
  dest := "IAMAPrivKeyTest.pem"
  privKey, errPriv := RSAPrivKeyLoad(&dest, false)
  if errPriv != nil {
    t.Errorf("FAIL - %v\n", errPriv)
  }
  validateErr := privKey.Validate()
  if validateErr != nil {
    t.Errorf("FAIL - %v\n", errPriv)
  }

  // Test saving a RSA public key
  dest = "IAMAPubKeyTest.pem"
  pubKey, errPub := RSAPubKeyLoad(&dest, false)
  if errPub != nil {
    _ = pubKey
    t.Errorf("FAIL - %v\n", errPub)
  }
}

```

## Additional Details

None

## Contributors

Brian Vohaska