package random

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

// MustGetRandomInt panics if it is unable to gather entropy in `rand.Reader`
func MustGetRandomInt(bits int) *big.Int {
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// TODO bubble err up
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
	}
	return n
}

func GetRandomPositiveInt(n *big.Int) *big.Int {
	var rnd *big.Int
	for {
		rnd = MustGetRandomInt(n.BitLen())
		if rnd.Cmp(n) < 0 && rnd.Cmp(zero) >= 0 {
			break
		}
	}
	return rnd
}

func GetRandomPrimeInt(bits int) *big.Int {
	rnd, err := rand.Prime(rand.Reader, bits)
	if err != nil ||
			rnd == nil ||
			rnd.Cmp(zero) == 0 {
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

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomPositiveRelativelyPrimeInt(n *big.Int) *big.Int {
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
	gcd := big.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}

//  Return a random generator of RQn with high probability.  THIS METHOD
//  ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!
// https://github.com/didiercrunch/paillier/blob/d03e8850a8e4c53d04e8016a2ce8762af3278b71/utils.go#L39
func GetRandomGeneratorOfTheQuadraticResidue(n *big.Int) *big.Int {
	r := GetRandomPositiveRelativelyPrimeInt(n)
	return new(big.Int).Mod(new(big.Int).Mul(r, r), n)
}
