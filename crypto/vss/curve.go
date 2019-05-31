package vss

import (
	s256k1 "github.com/btcsuite/btcd/btcec"
)

var (
	ec *s256k1.KoblitzCurve
)

func init() {
	ec = s256k1.S256()
}

func EC() *s256k1.KoblitzCurve {
	return ec
}
