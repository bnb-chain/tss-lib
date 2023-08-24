// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

func TestShareProtocol(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, pf, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	_, cB, betaPrm, pfB, err := BobMid(tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j)
	assert.NoError(t, err)

	alpha, err := AliceEnd(tss.EC(), pk, pfB, h1i, h2i, cA, cB, NTildei, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}

func TestShareProtocolWC(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)
	gBX, gBY := tss.EC().ScalarBaseMult(b.Bytes())

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, pf, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	gBPoint, err := crypto.NewECPoint(tss.EC(), gBX, gBY)
	assert.NoError(t, err)
	_, cB, betaPrm, pfB, err := BobMidWC(tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, gBPoint)
	assert.NoError(t, err)

	alpha, err := AliceEndWC(tss.EC(), pk, pfB, gBPoint, cA, cB, NTildei, h1i, h2i, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}
