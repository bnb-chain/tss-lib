package tss

import (
	"crypto/elliptic"

	s256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
)

var (
	ec elliptic.Curve
)

// Init default curve (secp256k1)
func init() {
	ec = s256k1.S256()
}

// EC returns the current elliptic curve in use. The default is secp256k1
func EC() elliptic.Curve {
	return ec
}

// SetCurve sets the curve used by TSS. Must be called before Start. The default is secp256k1
func SetCurve(curve elliptic.Curve) {
	if curve == nil {
		panic(errors.New("SetCurve received a nil curve"))
	}
	ec = curve
}
