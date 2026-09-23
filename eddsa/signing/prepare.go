// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
)

// PrepareForSigning(), Fig. 7
//
// Returns an error (instead of panicking) when any two party keys collide
// mod q or when the input sizes are inconsistent. tss.NewParameters
// enforces the mod-q distinctness invariant up-front, so a non-nil error
// here normally means a configuration was constructed via something other
// than NewParameters; callers should propagate the error rather than
// continuing.
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int) (wi *big.Int, err error) {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != pax {
		return nil, fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax)
	}
	if len(ks) <= i {
		return nil, fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i)
	}

	q := ec.Params().N
	// 1-4.
	wi = xi
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		// Compare the residues, not the raw bytes: distinct keys whose
		// mod-q residues collide would otherwise pass this check and
		// then trigger ModInverse(0, q) below. The shape of the bug
		// motivated the tss.NewParameters check; mirror it here for
		// callers that bypass NewParameters.
		if new(big.Int).Mod(ksj, q).Cmp(new(big.Int).Mod(ksi, q)) == 0 {
			return nil, fmt.Errorf("PrepareForSigning: party keys at indices %d and %d collide mod q", j, i)
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}

	return
}
