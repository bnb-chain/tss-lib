// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"errors"
	"math/big"
)

type SophieGermainPrime struct {
	sophiePrime,
	safePrime *big.Int
}

func (sgp *SophieGermainPrime) Prime() *big.Int {
	return sgp.sophiePrime
}

func (sgp *SophieGermainPrime) SafePrime() *big.Int {
	return sgp.safePrime
}

func (sgp *SophieGermainPrime) Validate() bool {
	return probablyPrime(sgp.sophiePrime) &&
		getSafePrime(sgp.sophiePrime).Cmp(sgp.safePrime) == 0 &&
		probablyPrime(sgp.safePrime)
}

// ----- //

func TrySophieGermainPrime(prime *big.Int) (*SophieGermainPrime, error) {
	if prime == nil {
		return nil, errors.New("the prime is nil")
	}
	if !probablyPrime(prime) {
		return nil, errors.New("the prime is not a prime")
	}
	sPrime := getSafePrime(prime)
	if !probablyPrime(sPrime) {
		return nil, errors.New("the prime is not a Sophie Germain prime")
	}
	return &SophieGermainPrime{prime, sPrime}, nil
}

func getSafePrime(p *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(p, two)
	i.Add(i, one)
	return i
}

func probablyPrime(prime *big.Int) bool {
	return prime != nil && prime.ProbablyPrime(primeTestN)
}
