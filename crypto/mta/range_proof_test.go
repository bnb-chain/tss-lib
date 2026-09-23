// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

func TestProveRangeAlice(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(rand.Reader, q)
	c, r, err := sk.EncryptAndReturnRandomness(rand.Reader, m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(Session, tss.EC(), pk, c, NTildei, h1i, h2i, m, r, rand.Reader)
	assert.NoError(t, err)

	ok := proof.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, c)
	assert.True(t, ok, "proof must verify")
}

func TestProveRangeAliceBypassed(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk0, pk0, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	m0 := common.GetRandomPositiveInt(rand.Reader, q)
	c0, r0, err := sk0.EncryptAndReturnRandomness(rand.Reader, m0)
	assert.NoError(t, err)

	primes0 := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	Ntildei0, h1i0, h2i0, err := crypto.GenerateNTildei(rand.Reader, primes0)
	assert.NoError(t, err)
	proof0, err := ProveRangeAlice(Session, tss.EC(), pk0, c0, Ntildei0, h1i0, h2i0, m0, r0, rand.Reader)
	assert.NoError(t, err)

	ok0 := proof0.Verify(Session, tss.EC(), pk0, Ntildei0, h1i0, h2i0, c0)
	assert.True(t, ok0, "proof must verify")

	// proof 2
	sk1, pk1, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	m1 := common.GetRandomPositiveInt(rand.Reader, q)
	c1, r1, err := sk1.EncryptAndReturnRandomness(rand.Reader, m1)
	assert.NoError(t, err)

	primes1 := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	Ntildei1, h1i1, h2i1, err := crypto.GenerateNTildei(rand.Reader, primes1)
	assert.NoError(t, err)
	proof1, err := ProveRangeAlice(Session, tss.EC(), pk1, c1, Ntildei1, h1i1, h2i1, m1, r1, rand.Reader)
	assert.NoError(t, err)

	ok1 := proof1.Verify(Session, tss.EC(), pk1, Ntildei1, h1i1, h2i1, c1)
	assert.True(t, ok1, "proof must verify")

	cross0 := proof0.Verify(Session, tss.EC(), pk1, Ntildei1, h1i1, h2i1, c1)
	assert.False(t, cross0, "proof must not verify")

	cross1 := proof1.Verify(Session, tss.EC(), pk0, Ntildei0, h1i0, h2i0, c0)
	assert.False(t, cross1, "proof must not verify")

	fmt.Println("Did verify proof 0 with data from 0?", ok0)
	fmt.Println("Did verify proof 1 with data from 1?", ok1)

	fmt.Println("Did verify proof 0 with data from 1?", cross0)
	fmt.Println("Did verify proof 1 with data from 0?", cross1)

	// new bypass
	bypassedproofNew := &RangeProofAlice{
		S:  big.NewInt(1),
		S1: big.NewInt(0),
		S2: big.NewInt(0),
		Z:  big.NewInt(1),
		U:  big.NewInt(1),
		W:  big.NewInt(1),
	}

	cBogus := big.NewInt(1)
	proofBogus, _ := ProveRangeAlice(Session, tss.EC(), pk1, cBogus, Ntildei1, h1i1, h2i1, m1, r1, rand.Reader)

	ok2 := proofBogus.Verify(Session, tss.EC(), pk1, Ntildei1, h1i1, h2i1, cBogus)
	bypassresult3 := bypassedproofNew.Verify(Session, tss.EC(), pk1, Ntildei1, h1i1, h2i1, cBogus)

	// c = 1 is not valid, even though we can find a range proof for it that passes!
	// this also means that the homo mul and add needs to be checked with this!
	fmt.Println("Did verify proof bogus with data from bogus?", ok2)
	fmt.Println("Did we bypass proof 3?", bypassresult3)
}

func TestRangeProofAliceRejectsOversizedS2(t *testing.T) {
	q := tss.EC().Params().N
	NTilde := big.NewInt(101)
	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	upperS2 := new(big.Int).Mul(q3, NTilde)
	upperS2.Lsh(upperS2, 1)

	proof := &RangeProofAlice{
		Z:  big.NewInt(2),
		U:  big.NewInt(2),
		W:  big.NewInt(2),
		S:  big.NewInt(2),
		S1: new(big.Int).Set(q),
		S2: upperS2,
	}
	pk := &paillier.PublicKey{N: big.NewInt(101)}

	assert.False(t, proof.Verify(Session, tss.EC(), pk, NTilde, big.NewInt(2), big.NewInt(3), big.NewInt(2)))
}

func TestRangeProofAliceVerifyRejectsMalformedInputs(t *testing.T) {
	q := tss.EC().Params().N
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)
	m := common.GetRandomPositiveInt(rand.Reader, q)
	c, r, err := sk.EncryptAndReturnRandomness(rand.Reader, m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NTilde, h1, h2, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(Session, tss.EC(), pk, c, NTilde, h1, h2, m, r, rand.Reader)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(Session, tss.EC(), pk, NTilde, h1, h2, c), "sanity: honest proof must verify")

	t.Run("prime pk.N", func(tt *testing.T) {
		primePk := &paillier.PublicKey{N: common.GetRandomPrimeInt(rand.Reader, 2048)}
		assert.False(tt, proof.Verify(Session, tss.EC(), primePk, NTilde, h1, h2, c))
	})
	t.Run("prime NTilde", func(tt *testing.T) {
		primeNTilde := common.GetRandomPrimeInt(rand.Reader, 2048)
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, primeNTilde, h1, h2, c))
	})
	t.Run("small NTilde", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, big.NewInt(101), h1, h2, c))
	})
	t.Run("h1 == h2", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, NTilde, h1, h1, c))
	})
	t.Run("h1 == 1", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, NTilde, big.NewInt(1), h2, c))
	})
	t.Run("c == 0", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, NTilde, h1, h2, big.NewInt(0)))
	})
	t.Run("c >= N^2 (non-canonical)", func(tt *testing.T) {
		nonCanonical := new(big.Int).Add(pk.NSquare(), c)
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, NTilde, h1, h2, nonCanonical))
	})
	t.Run("S shares factor with pk.N", func(tt *testing.T) {
		bad := *proof
		// sk.P is a prime factor of pk.N, so gcd(sk.P, pk.N) = sk.P > 1
		// while sk.P < pk.N keeps IsInInterval(S, pk.N) happy.
		bad.S = new(big.Int).Set(sk.P)
		assert.False(tt, bad.Verify(Session, tss.EC(), pk, NTilde, h1, h2, c))
	})
}

func TestProofBobWCVerifyRejectsMalformedInputs(t *testing.T) {
	q := tss.EC().Params().N
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits), common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits)}
	NTilde, h1, h2, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)

	// Alice's secret a (cA = Enc(a) using Alice's key), Bob's secret b. WC
	// proof attests cB = cA^b · Enc(betaPrm) with B = g^b, where Bob's
	// witness is (b, betaPrm, cRand).
	a := common.GetRandomPositiveInt(rand.Reader, q)
	b := common.GetRandomPositiveInt(rand.Reader, q)
	cA, _, err := sk.EncryptAndReturnRandomness(rand.Reader, a)
	assert.NoError(t, err)
	q5 := new(big.Int).Mul(q, q)
	q5 = new(big.Int).Mul(q5, q5)
	q5 = new(big.Int).Mul(q5, q)
	betaPrm := common.GetRandomPositiveInt(rand.Reader, q5)
	cBeta, cRand, err := pk.EncryptAndReturnRandomness(rand.Reader, betaPrm)
	assert.NoError(t, err)
	cB, err := pk.HomoMult(b, cA)
	assert.NoError(t, err)
	cB, err = pk.HomoAdd(cB, cBeta)
	assert.NoError(t, err)
	B := crypto.ScalarBaseMult(tss.EC(), b)
	proof, err := ProveBobWC(Session, tss.EC(), pk, NTilde, h1, h2, cA, cB, b, betaPrm, cRand, B, rand.Reader)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(Session, tss.EC(), pk, NTilde, h1, h2, cA, cB, B), "sanity: honest WC proof must verify")

	// Below the variables c1, c2, X mirror Alice's view (cA, cB, B).
	c1, c2, X := cA, cB, B

	t.Run("prime pk.N", func(tt *testing.T) {
		primePk := &paillier.PublicKey{N: common.GetRandomPrimeInt(rand.Reader, 2048)}
		assert.False(tt, proof.Verify(Session, tss.EC(), primePk, NTilde, h1, h2, c1, c2, X))
	})
	t.Run("prime NTilde", func(tt *testing.T) {
		primeNTilde := common.GetRandomPrimeInt(rand.Reader, 2048)
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, primeNTilde, h1, h2, c1, c2, X))
	})
	t.Run("h1 == h2", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, NTilde, h1, h1, c1, c2, X))
	})
	t.Run("c1 == 0", func(tt *testing.T) {
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, NTilde, h1, h2, big.NewInt(0), c2, X))
	})
	t.Run("c2 >= N^2 (non-canonical)", func(tt *testing.T) {
		nonCanonical := new(big.Int).Add(pk.NSquare(), c2)
		assert.False(tt, proof.Verify(Session, tss.EC(), pk, NTilde, h1, h2, c1, nonCanonical, X))
	})
}

func TestProofBobRejectsOversizedS2T2(t *testing.T) {
	q := tss.EC().Params().N
	NTilde := big.NewInt(101)
	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	upperS2T2 := new(big.Int).Mul(q3, NTilde)
	upperS2T2.Lsh(upperS2T2, 1)

	proof := &ProofBob{
		Z:    big.NewInt(2),
		ZPrm: big.NewInt(2),
		T:    big.NewInt(2),
		V:    big.NewInt(2),
		W:    big.NewInt(2),
		S:    big.NewInt(2),
		S1:   new(big.Int).Set(q),
		S2:   upperS2T2,
		T1:   new(big.Int).Set(q),
		T2:   new(big.Int).Set(q),
	}
	pk := &paillier.PublicKey{N: big.NewInt(101)}

	assert.False(t, proof.Verify(Session, tss.EC(), pk, NTilde, big.NewInt(2), big.NewInt(3), big.NewInt(2), big.NewInt(3)))
}
