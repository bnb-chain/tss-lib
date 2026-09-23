// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package facproof_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	. "github.com/bnb-chain/tss-lib/v4/crypto/facproof"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

var Session = []byte("session")

func TestFac(test *testing.T) {
	ec := tss.EC()

	N0p := common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)
	N0q := common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)
	N0 := new(big.Int).Mul(N0p, N0q)

	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(test, err)
	proof, err := NewProof(Session, ec, N0, NCap, s, t, N0p, N0q, rand.Reader)
	assert.NoError(test, err)

	ok := proof.Verify(Session, ec, N0, NCap, s, t)
	assert.True(test, ok, "proof must verify")

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	upperW := new(big.Int).Mul(q3, NCap)
	upperW.Lsh(upperW, 1)
	tampered := *proof
	tampered.W1 = upperW
	ok = tampered.Verify(Session, ec, N0, NCap, s, t)
	assert.False(test, ok, "proof with oversized W1 must be rejected before exponentiation")

	N0p = common.GetRandomPrimeInt(rand.Reader, 1024)
	N0q = common.GetRandomPrimeInt(rand.Reader, 1024)
	N0 = new(big.Int).Mul(N0p, N0q)

	proof, err = NewProof(Session, ec, N0, NCap, s, t, N0p, N0q, rand.Reader)
	assert.NoError(test, err)

	ok = proof.Verify(Session, ec, N0, NCap, s, t)
	assert.True(test, ok, "proof must verify")
}

func TestVerifyRejectsMalformedInputs(test *testing.T) {
	ec := tss.EC()
	N0p := common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)
	N0q := common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)
	N0 := new(big.Int).Mul(N0p, N0q)
	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(test, err)
	proof, err := NewProof(Session, ec, N0, NCap, s, t, N0p, N0q, rand.Reader)
	assert.NoError(test, err)

	test.Run("prime N0", func(tt *testing.T) {
		primeN0 := common.GetRandomPrimeInt(rand.Reader, 2048)
		assert.False(tt, proof.Verify(Session, ec, primeN0, NCap, s, t))
	})
	test.Run("prime NCap", func(tt *testing.T) {
		primeNCap := common.GetRandomPrimeInt(rand.Reader, 2048)
		assert.False(tt, proof.Verify(Session, ec, N0, primeNCap, s, t))
	})
	test.Run("small NCap", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, ec, N0, big.NewInt(15), s, t))
	})
	test.Run("s == t", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, ec, N0, NCap, s, s))
	})
	test.Run("s == 1", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, ec, N0, NCap, big.NewInt(1), t))
	})
	test.Run("t shares factor with NCap", func(tt *testing.T) {
		// primes[0] is one of the safe primes used to build NCap, so gcd > 1.
		assert.False(tt, proof.Verify(Session, ec, N0, NCap, s, primes[0]))
	})
	test.Run("P = 0", func(tt *testing.T) {
		bad := *proof
		bad.P = big.NewInt(0)
		assert.False(tt, bad.Verify(Session, ec, N0, NCap, s, t))
	})
	test.Run("A non-unit (factor of NCap)", func(tt *testing.T) {
		bad := *proof
		bad.A = new(big.Int).Set(primes[0])
		assert.False(tt, bad.Verify(Session, ec, N0, NCap, s, t))
	})
	test.Run("T = NCap", func(tt *testing.T) {
		bad := *proof
		bad.T = new(big.Int).Set(NCap)
		assert.False(tt, bad.Verify(Session, ec, N0, NCap, s, t))
	})
}
