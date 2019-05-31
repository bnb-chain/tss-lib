package math

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

func MustGetRandomInt(bits int) *big.Int {
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(int64(bits)), nil).Sub(max, big.NewInt(1))

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

func GetRandomPositiveRelativelyPrimeInt(n *big.Int) *big.Int {
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

func GetRandomPrimeInt(bits int) *big.Int {
	rnd, err := rand.Prime(rand.Reader, bits)
	if err != nil ||
			rnd == nil ||
			rnd.Cmp(big.NewInt(0)) == 0 {
		// fallback to older method
		for {
			rnd = MustGetRandomInt(bits)
			if rnd.ProbablyPrime(50) {
				break
			}
		}
	}
	return rnd
}
