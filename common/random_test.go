// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
)

const (
	randomIntBitLen = 1024
	// Every sampler below either returns immediately or never; the exact value
	// only has to be far above "immediately".
	samplerDeadline = 5 * time.Second
)

// returnsWithin runs fn on its own goroutine and reports whether it returned
// before d elapsed. On timeout fn is abandoned rather than joined: the inputs
// exercised below used to drive rejection loops whose acceptance probability is
// exactly zero, so waiting for them would hang `go test` itself. A panic inside
// fn is turned into a test failure instead of being allowed to take the whole
// test binary down.
func returnsWithin(t *testing.T, d time.Duration, fn func()) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("sampler panicked: %v", r)
			}
		}()
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func TestGetRandomInt(t *testing.T) {
	rnd := common.MustGetRandomInt(rand.Reader, randomIntBitLen)
	assert.NotZero(t, rnd, "rand int should not be zero")
}

func TestGetRandomPositiveInt(t *testing.T) {
	rnd := common.MustGetRandomInt(rand.Reader, randomIntBitLen)
	rndPos := common.GetRandomPositiveInt(rand.Reader, rnd)
	assert.NotZero(t, rndPos, "rand int should not be zero")
	assert.True(t, rndPos.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPositiveIntBoundaries(t *testing.T) {
	t.Run("nil lessThan returns nil", func(tt *testing.T) {
		assert.Nil(tt, common.GetRandomPositiveInt(rand.Reader, nil))
	})
	t.Run("lessThan == 0 returns nil", func(tt *testing.T) {
		assert.Nil(tt, common.GetRandomPositiveInt(rand.Reader, big.NewInt(0)))
	})
	t.Run("lessThan == 1 returns nil (no value in (0, 1))", func(tt *testing.T) {
		// Old implementation would loop forever sampling 0; new implementation
		// rejects up-front because (0, 1) is empty.
		assert.Nil(tt, common.GetRandomPositiveInt(rand.Reader, big.NewInt(1)))
	})
	t.Run("lessThan == 2 always returns 1", func(tt *testing.T) {
		// (0, 2) = {1} — sampler must return 1, never 0.
		for i := 0; i < 20; i++ {
			v := common.GetRandomPositiveInt(rand.Reader, big.NewInt(2))
			assert.NotNil(tt, v)
			assert.Equal(tt, int64(1), v.Int64())
		}
	})
}

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	rnd := common.MustGetRandomInt(rand.Reader, randomIntBitLen)
	rndPosRP := common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, rnd)
	assert.NotZero(t, rndPosRP, "rand int should not be zero")
	assert.True(t, common.IsNumberInMultiplicativeGroup(rnd, rndPosRP))
	assert.True(t, rndPosRP.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
	// TODO test for relative primeness
}

func TestGetRandomPositiveRelativelyPrimeIntBoundaries(t *testing.T) {
	t.Run("nil n returns nil", func(tt *testing.T) {
		assert.Nil(tt, common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, nil))
	})
	t.Run("n == 0 returns nil", func(tt *testing.T) {
		assert.Nil(tt, common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, big.NewInt(0)))
	})
	t.Run("n == 1 returns nil (no member of (Z/1Z)* exists)", func(tt *testing.T) {
		// The acceptance test IsNumberInMultiplicativeGroup wants 1 <= v < n,
		// which nothing satisfies for n == 1, so the sampler has no value to
		// return. The old guard only rejected n <= 0 and then looped forever:
		// MustGetRandomInt(rand, 1) draws from {0} without reading rand at all.
		var got *big.Int
		returned := returnsWithin(tt, samplerDeadline, func() {
			got = common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, big.NewInt(1))
		})
		assert.True(tt, returned, "must return rather than loop forever")
		assert.Nil(tt, got)
	})
	t.Run("n == 2 returns 1", func(tt *testing.T) {
		// (Z/2Z)* = {1}; the sampler must still find it.
		for i := 0; i < 20; i++ {
			v := common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, big.NewInt(2))
			assert.NotNil(tt, v)
			assert.Equal(tt, int64(1), v.Int64())
		}
	})
}

func TestGetRandomPrimeInt(t *testing.T) {
	prime := common.GetRandomPrimeInt(rand.Reader, randomIntBitLen)
	assert.NotZero(t, prime, "rand prime should not be zero")
	assert.True(t, prime.ProbablyPrime(50), "rand prime should be prime")
}

func TestGetRandomPrimeIntBoundaries(t *testing.T) {
	t.Run("bits <= 0 returns nil", func(tt *testing.T) {
		assert.Nil(tt, common.GetRandomPrimeInt(rand.Reader, 0))
		assert.Nil(tt, common.GetRandomPrimeInt(rand.Reader, -1))
	})
	t.Run("bits == 1 returns nil (no 1-bit prime exists)", func(tt *testing.T) {
		// crypto/rand.Prime's own contract is that it errors for bits < 2, and
		// the fallback loop cannot do better: MustGetRandomInt(rand, 1) draws
		// from {0}, so probablyPrime is asked about 0 forever.
		var got *big.Int
		returned := returnsWithin(tt, samplerDeadline, func() {
			got = common.GetRandomPrimeInt(rand.Reader, 1)
		})
		assert.True(tt, returned, "must return rather than loop forever")
		assert.Nil(tt, got)
	})
	t.Run("bits == 2 still returns a 2-bit prime", func(tt *testing.T) {
		for i := 0; i < 10; i++ {
			p := common.GetRandomPrimeInt(rand.Reader, 2)
			assert.NotNil(tt, p)
			assert.Equal(tt, 2, p.BitLen())
			assert.True(tt, p.ProbablyPrime(50))
		}
	})
}

func TestGetRandomQuadraticNonResidue(t *testing.T) {
	// n odd, > 1 and not a perfect square: a non-residue exists and must be found.
	for _, n := range []*big.Int{big.NewInt(15), big.NewInt(21), big.NewInt(2047)} {
		w := common.GetRandomQuadraticNonResidue(rand.Reader, n)
		assert.NotNil(t, w, "a non-residue exists mod %s", n)
		assert.Equal(t, -1, big.Jacobi(w, n))
	}
	p := common.GetRandomPrimeInt(rand.Reader, 256)
	q := common.GetRandomPrimeInt(rand.Reader, 256)
	n := new(big.Int).Mul(p, q)
	w := common.GetRandomQuadraticNonResidue(rand.Reader, n)
	assert.NotNil(t, w)
	assert.Equal(t, -1, big.Jacobi(w, n))
}

func TestGetRandomQuadraticNonResidueBoundaries(t *testing.T) {
	// Jacobi(w, m^2) = Jacobi(w, m)^2 is never -1, so for a perfect square the
	// loop's acceptance probability is exactly zero, not merely small. Same
	// verdict, different reason, for n <= 1 and for even n: big.Jacobi is only
	// defined for an odd modulus and GetRandomPositiveInt has nothing to hand
	// it for n <= 1.
	odd2048Square, ok := new(big.Int).SetString("9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001df280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018e9851", 16)
	assert.True(t, ok)
	for _, tc := range []struct {
		name string
		n    *big.Int
	}{
		{"nil", nil},
		{"zero", big.NewInt(0)},
		{"one", big.NewInt(1)},
		{"even", big.NewInt(8)},
		{"small perfect square", big.NewInt(9)},
		{"2048-bit odd perfect square", odd2048Square},
	} {
		t.Run(tc.name, func(tt *testing.T) {
			var got *big.Int
			returned := returnsWithin(tt, samplerDeadline, func() {
				got = common.GetRandomQuadraticNonResidue(rand.Reader, tc.n)
			})
			assert.True(tt, returned, "must return rather than loop forever")
			assert.Nil(tt, got)
		})
	}
}
