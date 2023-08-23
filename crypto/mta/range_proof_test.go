// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

func TestProveRangeAlice(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(q)
	c, r, err := sk.EncryptAndReturnRandomness(m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(primes)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(tss.EC(), pk, c, NTildei, h1i, h2i, m, r)
	assert.NoError(t, err)

	ok := proof.Verify(tss.EC(), pk, NTildei, h1i, h2i, c)
	assert.True(t, ok, "proof must verify")
}

func TestProveRangeAliceBypassed(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk0, pk0, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m0 := common.GetRandomPositiveInt(q)
	c0, r0, err := sk0.EncryptAndReturnRandomness(m0)
	assert.NoError(t, err)

	primes0 := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	Ntildei0, h1i0, h2i0, err := crypto.GenerateNTildei(primes0)
	assert.NoError(t, err)
	proof0, err := ProveRangeAlice(tss.EC(), pk0, c0, Ntildei0, h1i0, h2i0, m0, r0)
	assert.NoError(t, err)

	ok0 := proof0.Verify(tss.EC(), pk0, Ntildei0, h1i0, h2i0, c0)
	assert.True(t, ok0, "proof must verify")

	//proof 2
	sk1, pk1, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m1 := common.GetRandomPositiveInt(q)
	c1, r1, err := sk1.EncryptAndReturnRandomness(m1)
	assert.NoError(t, err)

	primes1 := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	Ntildei1, h1i1, h2i1, err := crypto.GenerateNTildei(primes1)
	assert.NoError(t, err)
	proof1, err := ProveRangeAlice(tss.EC(), pk1, c1, Ntildei1, h1i1, h2i1, m1, r1)
	assert.NoError(t, err)

	ok1 := proof1.Verify(tss.EC(), pk1, Ntildei1, h1i1, h2i1, c1)
	assert.True(t, ok1, "proof must verify")

	cross0 := proof0.Verify(tss.EC(), pk1, Ntildei1, h1i1, h2i1, c1)
	assert.False(t, cross0, "proof must not verify")

	cross1 := proof1.Verify(tss.EC(), pk0, Ntildei0, h1i0, h2i0, c0)
	assert.False(t, cross1, "proof must not verify")

	fmt.Println("Did verify proof 0 with data from 0?", ok0)
	fmt.Println("Did verify proof 1 with data from 1?", ok1)

	fmt.Println("Did verify proof 0 with data from 1?", cross0)
	fmt.Println("Did verify proof 1 with data from 0?", cross1)

	//new bypass
	bypassedproofNew := &RangeProofAlice{
		S:  big.NewInt(1),
		S1: big.NewInt(0),
		S2: big.NewInt(0),
		Z:  big.NewInt(1),
		U:  big.NewInt(1),
		W:  big.NewInt(1),
	}

	cBogus := big.NewInt(1)
	proofBogus, _ := ProveRangeAlice(tss.EC(), pk1, cBogus, Ntildei1, h1i1, h2i1, m1, r1)

	ok2 := proofBogus.Verify(tss.EC(), pk1, Ntildei1, h1i1, h2i1, cBogus)
	bypassresult3 := bypassedproofNew.Verify(tss.EC(), pk1, Ntildei1, h1i1, h2i1, cBogus)

	//c = 1 is not valid, even though we can find a range proof for it that passes!
	//this also means that the homo mul and add needs to be checked with this!
	fmt.Println("Did verify proof bogus with data from bogus?", ok2)
	fmt.Println("Did we bypass proof 3?", bypassresult3)
}
