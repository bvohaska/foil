# Cryptospecials Package

The crypospecials package contains most of the cryptographic components used in foil

Some of these components include,

* ec-based vrf

* rsa-based vrf

* ec-based OPRF

* RSA key generation

* ECDSA key generation

* MGF1

`cryptospecials.go` includes common functions that are used by many other functions in the cryptospecials package.

## Components in `cryptospecials.go`

The following fuinctions, structures, or variables are available,

### Available Variables

`blank` - A big.Int initialized with zeros but not equal to the integer zero

`zero` - big.Int integer zero

`one` - bit.Ing integer one

### Available Structures

`ECPoint` - A struct containing 2 big.Ints x and y representing an elliptic curve point

### Available Functions

`Hash2curve` - Hashes an integer `x` into an elliptic curve via the try-and-increment method

`hashThree` - A variadic function that performs the H_3 hash from <https://eprint.iacr.org/2017/099.pdf>

`mgf1XOR` - A version of MGF1 taken from the golang core

`incCounter` - A support function for `mgf1xor`

### Function Descriptions

`Hash2curve(data []byte, h hash.Hash, ec *elliptic.CurveParams, curveType int, verbose bool) (pt ECPoint, err error)`

This fuction attempts to hash `data` into the elliptic curve defined by `ec` via the try-and-increment method. While robust, this method is not constant-time nor is there a guarantee that the method will work within a reasonable time.

#### Input

data - information to be hashed into the elliptic curve

ec - elliptic curve parameters such as group order, base point, ...

curveType - (1) Weierstrass (2) others. Only (1) is supported currently

verbose - trigger verbose output

#### Output

pt - an elliptic curve point (x,y)

err - a standard formatted err

### Examples

RSA-based VRF generation,

```go

import (
  "crypto/elliptic"
  "crypto/sha256"
  "testing"
)

func TestHash2Curve(t *testing.T) {

  var (
    pt      ECPoint
    verbose bool
    err     error
  )

  verbose = true
  data := []byte("I'm a string!")
  hash256 := sha256.New()
  ec := elliptic.P256()

  pt, err = Hash2curve(data, hash256, ec.Params(), 1, verbose)
  if err != nil {
    t.Errorf("FAIL: %v\n", err)
  }
  if pt.x == zero || pt.y == zero {
    t.Errorf("FAIL: Zero values returned as points\n")
  }
}

```

## Additional Details

None

## Contributors

Brian Vohaska