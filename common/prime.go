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

type GermainPrime struct {
	germainPrime,
	safePrime *big.Int
}

func (sgp *GermainPrime) Prime() *big.Int {
	return sgp.germainPrime
}

func (sgp *GermainPrime) SafePrime() *big.Int {
	return sgp.safePrime
}

func (sgp *GermainPrime) Validate() bool {
	return probablyPrime(sgp.germainPrime) &&
		getSafePrime(sgp.germainPrime).Cmp(sgp.safePrime) == 0 &&
		probablyPrime(sgp.safePrime)
}

// ----- //

func TryGermainPrime(prime *big.Int) (*GermainPrime, error) {
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
	return &GermainPrime{prime, sPrime}, nil
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
