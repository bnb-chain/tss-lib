package math

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

func MustGetRandomInt(len int) *big.Int {
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(int64(len)), nil).Sub(max, big.NewInt(1))

	// Generate cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
	}
	return n
}

func GetRandomPositiveInt(n *big.Int) *big.Int {
	var rnd *big.Int
	zero := big.NewInt(0)

	for {
		rnd = MustGetRandomInt(n.BitLen())
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
		rnd = MustGetRandomInt(n.BitLen())
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
		rnd = MustGetRandomInt(length)
		if rnd.ProbablyPrime(512) {
			break
		}
	}

	return rnd
}
