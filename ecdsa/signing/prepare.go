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
	"github.com/bnb-chain/tss-lib/v4/crypto"
)

// PrepareForSigning(), GG18Spec (11) Fig. 14
//
// Returns an error (instead of panicking) when any two party keys collide
// mod q or when the input sizes are inconsistent. tss.NewParameters
// enforces the mod-q distinctness invariant up-front, so a non-nil error
// here normally means a configuration was constructed via something other
// than NewParameters; callers should propagate the error rather than
// continuing.
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int, bigXs []*crypto.ECPoint) (wi *big.Int, bigWs []*crypto.ECPoint, err error) {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != len(bigXs) {
		return nil, nil, fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)", len(ks), len(bigXs))
	}
	if len(ks) != pax {
		return nil, nil, fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax)
	}
	if len(ks) <= i {
		return nil, nil, fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i)
	}

	q := ec.Params().N
	// 2-4.
	wi = xi
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if new(big.Int).Mod(ksj, q).Cmp(new(big.Int).Mod(ksi, q)) == 0 {
			return nil, nil, fmt.Errorf("PrepareForSigning: party keys at indices %d and %d collide mod q", j, i)
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
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
			ksc := ks[c]
			ksj := ks[j]
			if new(big.Int).Mod(ksj, q).Cmp(new(big.Int).Mod(ksc, q)) == 0 {
				return nil, nil, fmt.Errorf("PrepareForSigning: party keys at indices %d and %d collide mod q", j, c)
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			iota := modQ.Mul(ksc, modQ.ModInverse(new(big.Int).Sub(ksc, ksj)))
			bigWj = bigWj.ScalarMult(iota)
			// SECURITY (SRC-2026-641): a nil result (degenerate identity) would
			// nil-deref on the next chained op or downstream X(); fail loudly.
			if bigWj == nil {
				return nil, nil, fmt.Errorf("PrepareForSigning: scalar mult produced a nil point at index %d", j)
			}
		}
		bigWs[j] = bigWj
	}
	return
}
