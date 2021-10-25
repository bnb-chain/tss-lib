// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"
	"runtime"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
)

const (
	safePrimeBitLen = 1024
)

var (
	one  = big.NewInt(1)
)

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
func GeneratePreParams(timeout time.Duration, optionalConcurrency ...int) (*LocalPreParams, error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}
	if concurrency /= 3; concurrency < 1 {
		concurrency = 1
	}

	common.Logger.Info("generating the safe primes for the signing proofs, please wait...")
	start := time.Now()
	sgps, err := common.GetRandomSafePrimesConcurrent(safePrimeBitLen, 2, timeout, concurrency)
	if err != nil {
		// ch <- nil
		return nil, err
	}
	common.Logger.Infof("safe primes generated. took %s\n", time.Since(start))

	if sgps == nil || sgps[0] == nil || sgps[1] == nil ||
		!sgps[0].Prime().ProbablyPrime(30) || !sgps[1].Prime().ProbablyPrime(30) ||
		!sgps[0].SafePrime().ProbablyPrime(30) || !sgps[1].SafePrime().ProbablyPrime(30) {
		return nil, errors.New("error while generating the safe primes")
	}

	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
	paiPK := &paillier.PublicKey{N: new(big.Int).Mul(P, Q)}
	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)
	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)
	paiSK := &paillier.PrivateKey{PublicKey: *paiPK, LambdaN: lambdaN, PhiN: phiN}
	NTildei := new(big.Int).Mul(P, Q)
	modNTildeI := common.ModInt(NTildei)

	p, q := sgps[0].Prime(), sgps[1].Prime()
	modPQ := common.ModInt(new(big.Int).Mul(p, q))
	f1 := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	beta := modPQ.ModInverse(alpha)
	h1i := modNTildeI.Mul(f1, f1)
	h2i := modNTildeI.Exp(h1i, alpha)

	preParams := &LocalPreParams{
		PaillierSK: paiSK,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
		Alpha:      alpha,
		Beta:       beta,
		P:          p,
		Q:          q,
	}
	return preParams, nil
}
