// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	cryptorand "crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/pkg/errors"
)

const (
	mustGetRandomIntMaxBits = 5000
	// Tries GetRandomQuadraticNonResidue makes before giving up; see the
	// derivation on that function.
	maxQuadraticNonResidueTries = 1024
)

// MustGetRandomInt panics if it is unable to gather entropy from `io.Reader` or when `bits` is <= 0
func MustGetRandomInt(rand io.Reader, bits int) *big.Int {
	if bits <= 0 || mustGetRandomIntMaxBits < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", mustGetRandomIntMaxBits))
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := cryptorand.Int(rand, max)
	if err != nil {
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
	}
	return n
}

// GetRandomPositiveInt returns a uniformly random integer in the open
// interval (0, lessThan). The lower bound is strict: 0 is never
// returned. This matches the name's "Positive" claim and the
// assumption made by every Verify-side `IsInIntervalPositive` check on
// values produced by this sampler.
//
// Returns nil if `lessThan` is nil, ≤ 1 (no value in (0, 1) exists),
// or if the underlying RNG misbehaves.
func GetRandomPositiveInt(rand io.Reader, lessThan *big.Int) *big.Int {
	if lessThan == nil || lessThan.Cmp(one) <= 0 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(rand, lessThan.BitLen())
		if try.Sign() > 0 && try.Cmp(lessThan) < 0 {
			break
		}
	}
	return try
}

// GetRandomPrimeInt returns a random prime of exactly `bits` bits.
//
// Returns nil when no such prime exists, i.e. for bits < 2: that is
// crypto/rand.Prime's own documented contract ("Prime will return an error ...
// if bits < 2"), and it has to be, since the only 1-bit values are 0 and 1 and
// neither is prime. The fallback loop below cannot do better either —
// MustGetRandomInt(rand, 1) draws from [0, 2^1-1) = {0} without reading rand
// at all — so the old `bits <= 0` guard let bits == 1 fall through into an
// unbounded loop asking probablyPrime(0).
func GetRandomPrimeInt(rand io.Reader, bits int) *big.Int {
	if bits < 2 {
		return nil
	}
	try, err := cryptorand.Prime(rand, bits)
	if err != nil ||
		try.Cmp(zero) == 0 {
		// fallback to older method
		for {
			try = MustGetRandomInt(rand, bits)
			if probablyPrime(try) {
				break
			}
		}
	}
	return try
}

// GetRandomPositiveRelativelyPrimeInt returns a uniformly random element of
// (Z/nZ)*, the group of elements of Z/nZ that have a multiplicative inverse.
//
// Returns nil if `n` is nil or ≤ 1. The acceptance test below,
// IsNumberInMultiplicativeGroup, wants 1 ≤ v < n, which no v satisfies for
// n ≤ 1, so there is no value to return. For n == 1 that was not merely
// unlikely but certain: MustGetRandomInt(rand, 1) draws from [0, 2^1-1) = {0}
// without reading rand at all, and 0 is never in the group, so the old guard —
// which only rejected n ≤ 0 — left a loop with acceptance probability exactly
// zero.
func GetRandomPositiveRelativelyPrimeInt(rand io.Reader, n *big.Int) *big.Int {
	if n == nil || n.Cmp(one) <= 0 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(rand, n.BitLen())
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

//	Return a random generator of RQn with high probability.
//	THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!
//
// https://github.com/didiercrunch/paillier/blob/d03e8850a8e4c53d04e8016a2ce8762af3278b71/utils.go#L39
func GetRandomGeneratorOfTheQuadraticResidue(rand io.Reader, n *big.Int) *big.Int {
	f := GetRandomPositiveRelativelyPrimeInt(rand, n)
	fSq := new(big.Int).Mul(f, f)
	return fSq.Mod(fSq, n)
}

// GetRandomQuadraticNonResidue returns a w ∈ (0, n) with Jacobi(w, n) = -1.
//
// It returns nil when n is outside the domain where such a w exists — n nil,
// n ≤ 1, n even, or n a perfect square — and nil in the vanishingly unlikely
// event that maxQuadraticNonResidueTries draws all missed. The preconditions
// used to be stated in this comment only ("of odd n"), while the loop below
// simply kept sampling; for a perfect square that loop had an acceptance
// probability of exactly zero, and for n ≤ 1 or even n big.Jacobi panics.
//
// WHY PERFECT SQUARES HAVE NO ANSWER. Jacobi(·, n) = Π_i Jacobi(·, p_i)^{e_i}
// over n = Π p_i^{e_i} is a homomorphism (Z/nZ)* → {±1}. Every exponent e_i of
// a perfect square is even, so the symbol is the constant 1 on units (and 0 on
// non-units): the value -1 is never taken, and no number of retries can find
// it. Conversely, if some e_i is odd, CRT gives a w that is a non-residue mod
// p_i and 1 elsewhere, so the homomorphism is onto and its kernel has index 2:
// exactly φ(n)/2 of the residues in (0, n) carry the symbol -1.
//
// TRY BOUND DERIVATION. Per the above, an admissible n has per-try success
// probability φ(n)/(2(n-1)) > φ(n)/2n. φ(n)/n = Π_{p|n}(1 - 1/p) shrinks only by
// admitting more distinct small primes, so for a bounded n it is minimised by
// the odd primorial 3·5·7·… — and n is bounded here, because GetRandomPositiveInt
// hands n.BitLen() to MustGetRandomInt, which panics above
// mustGetRandomIntMaxBits = 5000, so nothing wider ever reaches this loop. The
// largest odd primorial below 2^5000 is the product of the first 494 odd primes
// (4989 bits), with Π(1 - 1/p) = 0.1371…, giving a per-try success probability
// of at least 0.1371/2 > 1/16 for every n this function can be called with.
// All 1024 tries therefore miss with probability at most (15/16)^1024 < 2^-95.
// For the moduli this library actually samples over — products of two large
// primes — φ(n)/n > 1 - 2^-1000, the per-try probability is ~1/2 and the bound
// is ~2^-1024. The bound exists because the caller supplies the io.Reader:
// modproof.NewProof calls this while the party mutex is held, so a reader that
// has stopped producing entropy must not be able to park a party there forever.
func GetRandomQuadraticNonResidue(rand io.Reader, n *big.Int) *big.Int {
	if n == nil || n.Cmp(one) <= 0 || n.Bit(0) == 0 {
		return nil
	}
	if sqrt := new(big.Int).Sqrt(n); new(big.Int).Mul(sqrt, sqrt).Cmp(n) == 0 {
		return nil
	}
	for i := 0; i < maxQuadraticNonResidueTries; i++ {
		w := GetRandomPositiveInt(rand, n)
		if big.Jacobi(w, n) == -1 {
			return w
		}
	}
	return nil
}

// GetRandomBytes returns random bytes of length.
func GetRandomBytes(rand io.Reader, length int) ([]byte, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if length <= 0 {
		return nil, errors.New("invalid length")
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
