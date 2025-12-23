// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

func TestShareProtocol(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, rA, err := pk.EncryptAndReturnRandomness(a)
	assert.NoError(t, err)
	pf, err := AliceInit(pk, a, cA, rA, NTildej, h1j, h2j)
	assert.NoError(t, err)

	_, cB, betaPrm, pfB, err := BobMid(pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j)
	assert.NoError(t, err)

	alpha, err := AliceEnd(pk, pfB, h1i, h2i, cA, cB, NTildei, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}

func TestShareProtocolWC(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)
	gBX, gBY := tss.EC().ScalarBaseMult(b.Bytes())

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, rA, err := pk.EncryptAndReturnRandomness(a)
	assert.NoError(t, err)
	pf, err := AliceInit(pk, a, cA, rA, NTildej, h1j, h2j)
	assert.NoError(t, err)

	gBPoint, err := crypto.NewECPoint(tss.EC(), gBX, gBY)
	assert.NoError(t, err)
	betaPrm, cB, pfB, err := BobMidWC(pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, gBPoint)
	assert.NoError(t, err)

	muIJ, _, muRandIJ, err := AliceEndWC(pk, pfB, gBPoint, cA, cB, NTildei, h1i, h2i, sk)
	assert.NoError(t, err)
	assert.NotNil(t, muRandIJ)

	// expect: muIJ = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, muIJ.Cmp(aTimesBPlusBetaModQ))
}
