// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
)

const (
	primeTestN = 30
)

type (
	GermainSafePrime struct {
		q,
		p *big.Int // p = 2q + 1
	}
)

func (sgp *GermainSafePrime) Prime() *big.Int {
	return sgp.q
}

func (sgp *GermainSafePrime) SafePrime() *big.Int {
	return sgp.p
}

func (sgp *GermainSafePrime) Validate() bool {
	return probablyPrime(sgp.q) &&
		getSafePrime(sgp.q).Cmp(sgp.p) == 0 &&
		probablyPrime(sgp.p)
}

// ----- //

func getSafePrime(p *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(p, two)
	i.Add(i, one)
	return i
}

func probablyPrime(prime *big.Int) bool {
	return prime != nil && prime.ProbablyPrime(primeTestN)
}

// ----- //

// The following code is a modified copy of: https://github.com/didiercrunch/paillier/blob/753322e473bf8ee20267c7824e68ae47360cc69b/safe_prime_generator.go
// It is an implementation of the algorithm described in "Safe Prime Generation with a Combined Sieve" https://eprint.iacr.org/2003/186.pdf

// The code is the original Go implementation of rand.Prime optimized for
// generating safe (Sophie Germain) primes.
// A safe prime is a prime number of the form 2p + 1, where p is also a prime.

// Note from Author (https://github.com/pdyraga):
// I've adapted a Go code for generating random numbers by inserting some
// optimisations that will allow us to generate safe primes faster than
// with the previous, naive approach.
//
// First of all, having q which can be prime, we first check whether q%3=1.
// If that's true, there is no chance p=2q+1 is prime. It lets us to reject
// candidate numbers quicker without running an expensive primality tests.
//
// Also, before we run a primality test for q, we may check p=2q+1 against
// the primes between 3-53 (We are limited by Go's uint64 range).
//
// If all those conditions are met and we know p is prime, it's enough to
// check Pocklington criterion for q instead of running an expensive
// primality test for it.

// smallPrimes is a list of small, prime numbers that allows us to rapidly
// exclude some fraction of composite candidates when searching for a random
// prime. This list is truncated at the point where smallPrimesProduct exceeds
// a uint64. It does not include two because we ensure that the candidates are
// odd by construction.
var smallPrimes = []uint8{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

// smallPrimesProduct is the product of the values in smallPrimes and allows us
// to reduce a candidate prime by this number and then determine whether it's
// coprime to all the elements of smallPrimes without further big.Int
// operations.
var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)

// ErrGeneratorCancelled is an error returned from GetRandomSafePrimesConcurrent
// when the work of the generator has been cancelled as a result of the context
// being done (cancellation or timeout).
var ErrGeneratorCancelled = fmt.Errorf("generator work cancelled")

// GetRandomSafePrimesConcurrent tries to find safe primes concurrently.
// The returned results are safe primes `p` and prime `q` such that `p=2q+1`.
// Concurrency level can be controlled with the `concurrencyLevel` parameter.
// If a safe prime could not be found before the context is done, the error
// is returned. Also, if at least one search process failed, error is returned
// as well.
//
// How fast we generate a prime number is mostly a matter of luck and it depends
// on how lucky we are with drawing the first bytes.
// With today's multi-core processors, we can execute the process on multiple
// cores concurrently, accept the first valid result and cancel the rest of
// work. This way, with the same finding algorithm, we can get the result
// faster.
//
// Concurrency level should be set depending on what `bitLen` of prime is
// expected. For example, as of today, on a typical workstation, for 512-bit
// safe prime, `concurrencyLevel` should be set to `1` as generating the prime
// of this length is a matter of milliseconds for a single core.
// For 1024-bit safe prime, `concurrencyLevel` should be usually set to at least
// `2` and for 2048-bit safe prime, `concurrencyLevel` must be set to at least
// `4` to get the result in a reasonable time.
//
// This function generates safe primes of at least 6 `bitLen`. For every
// generated safe prime, the two most significant bits are always set to `1`
// - we don't want the generated number to be too small.
func GetRandomSafePrimesConcurrent(ctx context.Context, bitLen, numPrimes int, concurrency int) ([]*GermainSafePrime, error) {
	if bitLen < 6 {
		return nil, errors.New("safe prime size must be at least 6 bits")
	}
	if numPrimes < 1 {
		return nil, errors.New("numPrimes should be > 0")
	}

	primeCh := make(chan *GermainSafePrime, concurrency*numPrimes)
	errCh := make(chan error, concurrency*numPrimes)
	primes := make([]*GermainSafePrime, 0, numPrimes)

	waitGroup := &sync.WaitGroup{}

	defer close(primeCh)
	defer close(errCh)
	defer waitGroup.Wait()

	generatorCtx, cancelGeneratorCtx := context.WithCancel(ctx)
	defer cancelGeneratorCtx()

	for i := 0; i < concurrency; i++ {
		waitGroup.Add(1)
		runGenPrimeRoutine(
			generatorCtx, primeCh, errCh, waitGroup, rand.Reader, bitLen,
		)
	}

	needed := int32(numPrimes)
	for {
		select {
		case result := <-primeCh:
			primes = append(primes, result)
			if atomic.AddInt32(&needed, -1) <= 0 {
				return primes[:numPrimes], nil
			}
		case err := <-errCh:
			return nil, err
		case <-ctx.Done():
			return nil, ErrGeneratorCancelled
		}
	}
}

// Starts a Goroutine searching for a safe prime of the specified `pBitLen`.
// If succeeds, writes prime `p` and prime `q` such that `p = 2q+1` to the
// `primeCh`. Prime `p` has a bit length equal to `pBitLen` and prime `q` has
// a bit length equal to `pBitLen-1`.
//
// The algorithm is as follows:
//  1. Generate a random odd number `q` of length `pBitLen-1` with two the most
//     significant bits set to `1`.
//  2. Execute preliminary primality test on `q` checking whether it is coprime
//     to all the elements of `smallPrimes`. It allows to eliminate trivial
//     cases quickly, when `q` is obviously no prime, without running an
//     expensive final primality tests.
//     If `q` is coprime to all of the `smallPrimes`, then go to the point 3.
//     If not, add `2` and try again. Do it at most 10 times.
//  3. Check the potentially prime `q`, whether `q = 1 (mod 3)`. This will
//     happen for 50% of cases.
//     If it is, then `p = 2q+1` will be a multiple of 3, so it will be obviously
//     not a prime number. In this case, add `2` and try again. Do it at most 10
//     times. If `q != 1 (mod 3)`, go to the point 4.
//  4. Now we know `q` is potentially prime and `p = 2q+1` is not a multiple of
//  3. We execute a preliminary primality test on `p`, checking whether
//     it is coprime to all the elements of `smallPrimes` just like we did for
//     `q` in point 2. If `p` is not coprime to at least one element of the
//     `smallPrimes`, then go back to point 1.
//     If `p` is coprime to all the elements of `smallPrimes`, go to point 5.
//  5. At this point, we know `q` is potentially prime, and `p=q+1` is also
//     potentially prime. We need to execute a final primality test for `q`.
//     We apply Miller-Rabin and Baillie-PSW tests. If they succeed, it means
//     that `q` is prime with a very high probability. Knowing `q` is prime,
//     we use Pocklington's criterion to prove the primality of `p=2q+1`, that
//     is, we execute Fermat primality test to base 2 checking whether
//     `2^{p-1} = 1 (mod p)`. It's significantly faster than running full
//     Miller-Rabin and Baillie-PSW for `p`.
//     If `q` and `p` are found to be prime, return them as a result. If not, go
//     back to the point 1.
func runGenPrimeRoutine(
	ctx context.Context,
	primeCh chan<- *GermainSafePrime,
	errCh chan<- error,
	waitGroup *sync.WaitGroup,
	rand io.Reader,
	pBitLen int,
) {
	qBitLen := pBitLen - 1
	b := uint(qBitLen % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (qBitLen+7)/8)
	p := new(big.Int)
	q := new(big.Int)

	bigMod := new(big.Int)

	go func() {
		defer waitGroup.Done()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				_, err := io.ReadFull(rand, bytes)
				if err != nil {
					errCh <- err
					return
				}

				// Clear bits in the first byte to make sure the candidate has
				// a size <= bits.
				bytes[0] &= uint8(int(1<<b) - 1)
				// Don't let the value be too small, i.e, set the most
				// significant two bits.
				// Setting the top two bits, rather than just the top bit,
				// means that when two of these values are multiplied together,
				// the result isn't ever one bit short.
				if b >= 2 {
					bytes[0] |= 3 << (b - 2)
				} else {
					// Here b==1, because b cannot be zero.
					bytes[0] |= 1
					if len(bytes) > 1 {
						bytes[1] |= 0x80
					}
				}
				// Make the value odd since an even number this large certainly
				// isn't prime.
				bytes[len(bytes)-1] |= 1

				q.SetBytes(bytes)

				// Calculate the value mod the product of smallPrimes. If it's
				// a multiple of any of these primes we add two until it isn't.
				// The probability of overflowing is minimal and can be ignored
				// because we still perform Miller-Rabin tests on the result.
				bigMod.Mod(q, smallPrimesProduct)
				mod := bigMod.Uint64()

			NextDelta:
				for delta := uint64(0); delta < 1<<20; delta += 2 {
					m := mod + delta
					for _, prime := range smallPrimes {
						if m%uint64(prime) == 0 && (qBitLen > 6 || m != uint64(prime)) {
							continue NextDelta
						}
					}

					if delta > 0 {
						bigMod.SetUint64(delta)
						q.Add(q, bigMod)
					}

					// If `q = 1 (mod 3)`, then `p` is a multiple of `3` so it's
					// obviously no prime and such `q` should be rejected.
					// This will happen in 50% of cases and we should detect
					// and eliminate them early.
					//
					// Explanation:
					// If q = 1 (mod 3) then there exists a q' such that:
					// q = 3q' + 1
					//
					// Since p = 2q + 1:
					// p = 2q + 1 = 2(3q' + 1) + 1 = 6q' + 2 + 1 = 6q' + 3 =
					//   = 3(2q' + 1)
					// So `p` is a multiple of `3`.
					qMod3 := new(big.Int).Mod(q, big.NewInt(3))
					if qMod3.Cmp(big.NewInt(1)) == 0 {
						continue NextDelta
					}

					// p = 2q+1
					p.Mul(q, big.NewInt(2))
					p.Add(p, big.NewInt(1))
					if !isPrimeCandidate(p) {
						continue NextDelta
					}

					break
				}

				// There is a tiny possibility that, by adding delta, we caused
				// the number to be one bit too long. Thus we check BitLen
				// here.
				if q.ProbablyPrime(20) &&
					isPocklingtonCriterionSatisfied(p) &&
					q.BitLen() == qBitLen {

					if sgp := (&GermainSafePrime{p: p, q: q}); sgp.Validate() {
						primeCh <- &GermainSafePrime{p: p, q: q}
					}
					p, q = new(big.Int), new(big.Int)
				}
			}
		}
	}()
}

// Pocklington's criterion can be used to prove the primality of `p = 2q + 1`
// once one has proven the primality of `q`.
// With `q` prime, `p = 2q + 1`, and `p` passing Fermat's primality test to base
// `2` that `2^{p-1} = 1 (mod p)` then `p` is prime as well.
func isPocklingtonCriterionSatisfied(p *big.Int) bool {
	return new(big.Int).Exp(
		big.NewInt(2),
		new(big.Int).Sub(p, big.NewInt(1)),
		p,
	).Cmp(big.NewInt(1)) == 0
}

func isPrimeCandidate(number *big.Int) bool {
	m := new(big.Int).Mod(number, smallPrimesProduct).Uint64()
	for _, prime := range smallPrimes {
		if m%uint64(prime) == 0 && m != uint64(prime) {
			return false
		}
	}
	return true
}
