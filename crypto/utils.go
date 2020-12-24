// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/btcsuite/btcd/btcec"

	"github.com/binance-chain/tss-lib/common"
)

var (
	basePoint2Cache = new(sync.Map)
)

// ECBasePoint2 returns a shared point of unknown discrete logarithm for the given curve, used only in GG20 ECDSA signing phase 3 (as h)
// Mimics the KZen-networks/curv impl: https://git.io/JfwSa
// Not so efficient due to 3x sha256 but it's only used once during a signing round.
func ECBasePoint2(curve elliptic.Curve) (pt *ECPoint, err error) {
	if curve == nil {
		return nil, errors.New("ECBasePoint2() received a nil curve")
	}
	if pt, ok := basePoint2Cache.Load(curve); ok {
		return pt.(*ECPoint), nil
	}
	minRounds := 3 // minimum to generate a curve point for secp256k1
	params := curve.Params()
	G := btcec.PublicKey{
		Curve: curve,
		X:     params.Gx,
		Y:     params.Gy,
	}
	bz := G.SerializeCompressed()
	for i := 0; i < minRounds || pt == nil; i++ {
		if i >= 10 {
			err = errors.New("ECBasePoint2() too many rounds (max: 10)")
			return
		}
		sum := sha256.Sum256(bz)
		bz = sum[:]
		if i >= minRounds-1 {
			pt, _ = DecompressPoint(curve, new(big.Int).SetBytes(bz), 0x2)
		}
	}
	basePoint2Cache.Store(curve, pt)
	return
}

func GenerateNTildei(safePrimes [2]*big.Int) (NTildei, h1i, h2i *big.Int, err error) {
	if safePrimes[0] == nil || safePrimes[1] == nil {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: needs two primes, got %v", safePrimes)
	}
	if !safePrimes[0].ProbablyPrime(30) || !safePrimes[1].ProbablyPrime(30) {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: expected two primes")
	}
	NTildei = new(big.Int).Mul(safePrimes[0], safePrimes[1])
	h1 := common.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	h2 := common.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	return NTildei, h1, h2, nil
}
