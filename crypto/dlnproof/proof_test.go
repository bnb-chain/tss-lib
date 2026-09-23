// Copyright © 2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnproof_test

import (
	"context"
	"crypto/rand"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	. "github.com/bnb-chain/tss-lib/v4/crypto/dlnproof"
)

var (
	fixtureOnce  sync.Once
	fixtureH1    *big.Int
	fixtureH2    *big.Int
	fixtureN     *big.Int
	fixtureP     *big.Int
	fixtureQ     *big.Int
	fixtureAlpha *big.Int
	fixtureErr   error
)

// loadFixture lazily generates one set of safe-prime / h1 / h2 / alpha
// parameters and reuses them across subtests. Generating two 1024-bit safe
// primes via GetRandomSafePrimesConcurrent takes seconds; the brute-force
// "GetRandomPrimeInt then check 2p+1" loop is ~150s, hence the dedicated
// helper.
func loadFixture(t *testing.T) {
	t.Helper()
	fixtureOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		sgps, err := common.GetRandomSafePrimesConcurrent(ctx, 1024, 2, runtime.NumCPU(), rand.Reader)
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureP, fixtureQ = sgps[0].Prime(), sgps[1].Prime()
		P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
		fixtureN = new(big.Int).Mul(P, Q)
		modN := common.ModInt(fixtureN)
		f1 := common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, fixtureN)
		fixtureH1 = modN.Mul(f1, f1)
		fixtureAlpha = common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, fixtureN)
		fixtureH2 = modN.Exp(fixtureH1, fixtureAlpha)
	})
	assert.NoError(t, fixtureErr)
}

var Session = []byte("session")

func TestDLNVerifyRejectsMalformedInputs(test *testing.T) {
	loadFixture(test)
	h1, h2, N, p, q, alpha := fixtureH1, fixtureH2, fixtureN, fixtureP, fixtureQ, fixtureAlpha
	pf := NewDLNProof(Session, h1, h2, alpha, p, q, N, rand.Reader)
	assert.True(test, pf.Verify(Session, h1, h2, N), "sanity: honest proof must verify")

	test.Run("nil N", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, h1, h2, nil))
	})
	test.Run("prime N", func(tt *testing.T) {
		primeN := common.GetRandomPrimeInt(rand.Reader, 2048)
		assert.False(tt, pf.Verify(Session, h1, h2, primeN))
	})
	test.Run("small N", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, h1, h2, big.NewInt(15)))
	})
	test.Run("h1 = 1", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, big.NewInt(1), h2, N))
	})
	test.Run("h1 = 0", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, big.NewInt(0), h2, N))
	})
	test.Run("h1 = N (non-canonical)", func(tt *testing.T) {
		// h1 mod N == 0 would have passed via the earlier Mod-based check
		// if it had landed in (1, N) after reduction; the canonical-input
		// requirement rejects this on the raw value instead.
		assert.False(tt, pf.Verify(Session, new(big.Int).Set(N), h2, N))
	})
	test.Run("h1 + N (non-canonical)", func(tt *testing.T) {
		nonCanonical := new(big.Int).Add(h1, N)
		assert.False(tt, pf.Verify(Session, nonCanonical, h2, N))
	})
	test.Run("h1 shares factor with N", func(tt *testing.T) {
		// p is one of the Germain primes; (2p+1) divides N, not p. But
		// gcd(p, N) is generally 1 since N's prime factors are 2p+1 and
		// 2q+1, not p and q. Use a value with a small shared factor by
		// constructing 2*p+1 directly:
		nonUnit := new(big.Int).Lsh(p, 1)
		nonUnit.Add(nonUnit, big.NewInt(1))
		assert.False(tt, pf.Verify(Session, nonUnit, h2, N))
	})
	test.Run("h1 == h2", func(tt *testing.T) {
		assert.False(tt, pf.Verify(Session, h1, h1, N))
	})
	_ = q
}
