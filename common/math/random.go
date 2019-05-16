package math

import (
	"math/big"
	"math/rand"
	"time"
)

func GetRandomInt(length int) *big.Int {
	// NewInt allocates and returns a new Int set to x.
	one := big.NewInt(1)
	// Lsh sets z = x << n and returns z.
	maxi := new(big.Int).Lsh(one, uint(length))

	// New returns a new Rand that uses random values from src to generate other random values.
	// NewSource returns a new pseudo-random Source seeded with the given value.
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Returns a pseudo-random number in (0, n)
	return new(big.Int).Rand(random, maxi)
}

func GetRandomPositiveInt(n *big.Int) *big.Int {
	var rnd *big.Int
	zero := big.NewInt(0)

	for {
		rnd = GetRandomInt(n.BitLen())
		if rnd.Cmp(n) < 0 && rnd.Cmp(zero) >= 0 {
			break
		}
	}

	return rnd
}

func GetRandomPositiveIntStar(n *big.Int) *big.Int {
	var rnd *big.Int
	gcd := big.NewInt(0)
	one := big.NewInt(1)

	for {
		rnd = GetRandomInt(n.BitLen())
		if rnd.Cmp(n) < 0 && rnd.Cmp(one) >= 0 &&
				gcd.GCD(nil, nil, rnd, n).Cmp(one) == 0 {
			break
		}
	}

	return rnd
}

func GetRandomPrimeInt(length int) *big.Int {
	var rnd *big.Int

	for {
		rnd = GetRandomInt(length)
		if rnd.ProbablyPrime(512) {
			break
		}
	}

	return rnd
}
