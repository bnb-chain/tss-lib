package schnorrZK

import (
	s256k1 "github.com/btcsuite/btcd/btcec"
)

var (
	EC *s256k1.KoblitzCurve
)

func init() {
	EC = s256k1.S256()
}
