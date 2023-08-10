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

	sk_0, pk_0, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m_0 := common.GetRandomPositiveInt(q)
	c_0, r_0, err := sk_0.EncryptAndReturnRandomness(m_0)
	assert.NoError(t, err)

	primes_0 := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei_0, h1i_0, h2i_0, err := crypto.GenerateNTildei(primes_0)
	assert.NoError(t, err)
	proof_0, err := ProveRangeAlice(tss.EC(), pk_0, c_0, NTildei_0, h1i_0, h2i_0, m_0, r_0)
	assert.NoError(t, err)

	ok_0 := proof_0.Verify(tss.EC(), pk_0, NTildei_0, h1i_0, h2i_0, c_0)
	assert.True(t, ok_0, "proof must verify")

	//proof 2
	sk_1, pk_1, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m_1 := common.GetRandomPositiveInt(q)
	c_1, r_1, err := sk_1.EncryptAndReturnRandomness(m_1)
	assert.NoError(t, err)

	primes_1 := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei_1, h1i_1, h2i_1, err := crypto.GenerateNTildei(primes_1)
	assert.NoError(t, err)
	proof_1, err := ProveRangeAlice(tss.EC(), pk_1, c_1, NTildei_1, h1i_1, h2i_1, m_1, r_1)
	assert.NoError(t, err)

	ok_1 := proof_1.Verify(tss.EC(), pk_1, NTildei_1, h1i_1, h2i_1, c_1)
	assert.True(t, ok_1, "proof must verify")

	cross_0 := proof_0.Verify(tss.EC(), pk_1, NTildei_1, h1i_1, h2i_1, c_1)
	assert.False(t, cross_0, "proof must not verify")

	cross_1 := proof_1.Verify(tss.EC(), pk_0, NTildei_0, h1i_0, h2i_0, c_0)
	assert.False(t, cross_1, "proof must not verify")

	fmt.Println("Did verify proof 0 with data from 0?", ok_0)
	fmt.Println("Did verify proof 1 with data from 1?", ok_1)

	fmt.Println("Did verify proof 0 with data from 1?", cross_0)
	fmt.Println("Did verify proof 1 with data from 0?", cross_1)

	//always passes
	bypassedProof := &RangeProofAlice{
		S:  big.NewInt(0),
		S1: big.NewInt(0),
		S2: big.NewInt(0),
		Z:  big.NewInt(1),
		U:  big.NewInt(0),
		W:  big.NewInt(1),
	}

	bypassResult_1 := bypassedProof.Verify(tss.EC(), pk_0, NTildei_0, h1i_0, h2i_0, c_0)
	fmt.Println("Did we bypass proof 1?", bypassResult_1)
	bypassResult_2 := bypassedProof.Verify(tss.EC(), pk_1, NTildei_1, h1i_1, h2i_1, c_1)
	fmt.Println("Did we bypass proof 2?", bypassResult_2)
}
