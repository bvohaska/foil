package cryptospecials

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
	if pt.X == zero || pt.Y == zero {
		t.Errorf("FAIL: Zero values returned as points\n")
	}
}
