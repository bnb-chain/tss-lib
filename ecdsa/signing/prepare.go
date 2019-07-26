package signing

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

// PrepareForSigning(), GG18Spec (11) Fig. 14
func PrepareForSigning(i, pax int, xi *big.Int, ks []*big.Int, bigXs []*crypto.ECPoint) (wi *big.Int, bigWs []*crypto.ECPoint) {
	modQ := common.ModInt(tss.EC().Params().N)

	// 2-4.
	wi = xi
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		kj, ki := ks[j], ks[i]
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		coef := modQ.Mul(kj, modQ.ModInverse(new(big.Int).Sub(kj, ki)))
		wi = modQ.Mul(wi, coef)
	}

	// 5-10.
	bigWs = make([]*crypto.ECPoint, len(ks))
	for j := 0; j < pax; j++ {
		bigWj := bigXs[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			iota := modQ.Mul(ks[c], modQ.ModInverse(new(big.Int).Sub(ks[c], ks[j])))
			bigWj = bigWj.ScalarMult(iota)
		}
		bigWs[j] = bigWj
	}
	return
}
