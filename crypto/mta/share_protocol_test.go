// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

var Session = []byte("session")

func TestShareProtocol(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(rand.Reader, q)
	b := common.GetRandomPositiveInt(rand.Reader, q)

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, pf, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j, rand.Reader)
	assert.NoError(t, err)

	_, cB, betaPrm, pfB, err := BobMid(Session, tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, rand.Reader)
	assert.NoError(t, err)

	alpha, err := AliceEnd(Session, tss.EC(), pk, pfB, h1i, h2i, cA, cB, NTildei, sk)
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

	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(rand.Reader, q)
	b := common.GetRandomPositiveInt(rand.Reader, q)
	gBX, gBY := tss.EC().ScalarBaseMult(b.Bytes())

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, pf, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j, rand.Reader)
	assert.NoError(t, err)

	gBPoint, err := crypto.NewECPoint(tss.EC(), gBX, gBY)
	assert.NoError(t, err)
	_, cB, betaPrm, pfB, err := BobMidWC(Session, tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, gBPoint, rand.Reader)
	assert.NoError(t, err)

	alpha, err := AliceEndWC(Session, tss.EC(), pk, pfB, gBPoint, cA, cB, NTildei, h1i, h2i, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}
