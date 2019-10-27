// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
)

const (
	mustGetRandomIntMaxBits = 5000
)

// MustGetRandomInt panics if it is unable to gather entropy from `rand.Reader` or when `bits` is <= 0
func MustGetRandomInt(bits int) *big.Int {
	if bits <= 0 || mustGetRandomIntMaxBits < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", mustGetRandomIntMaxBits))
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
	}
	return n
}

func GetRandomPositiveInt(lessThan *big.Int) *big.Int {
	if lessThan == nil || zero.Cmp(lessThan) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(lessThan.BitLen())
		if try.Cmp(lessThan) < 0 && try.Cmp(zero) >= 0 {
			break
		}
	}
	return try
}

func GetRandomPrimeInt(bits int) *big.Int {
	if bits <= 0 {
		return nil
	}
	try, err := rand.Prime(rand.Reader, bits)
	if err != nil ||
		try.Cmp(zero) == 0 {
		// fallback to older method
		for {
			try = MustGetRandomInt(bits)
			if probablyPrime(try) {
				break
			}
		}
	}
	return try
}

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomPositiveRelativelyPrimeInt(n *big.Int) *big.Int {
	if n == nil || zero.Cmp(n) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(n.BitLen())
		if IsNumberInMultiplicativeGroup(n, try) {
			break
		}
	}
	return try
}

func IsNumberInMultiplicativeGroup(n, v *big.Int) bool {
	if n == nil || v == nil || zero.Cmp(n) != -1 {
		return false
	}
	gcd := big.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}

//  Return a random generator of RQn with high probability.
//  THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!
// https://github.com/didiercrunch/paillier/blob/d03e8850a8e4c53d04e8016a2ce8762af3278b71/utils.go#L39
func GetRandomGeneratorOfTheQuadraticResidue(n *big.Int) *big.Int {
	f := GetRandomPositiveRelativelyPrimeInt(n)
	fSq := new(big.Int).Mul(f, f)
	return fSq.Mod(fSq, n)
}
