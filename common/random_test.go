// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
)

const (
	randomIntLength = 1024
)

func TestGetRandomInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntLength)
	assert.NotZero(t, rnd, "rand int should not be zero")
}

func TestGetRandomPositiveInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntLength)
	rndPos := common.GetRandomPositiveInt(rnd)
	assert.NotZero(t, rndPos, "rand int should not be zero")
	assert.True(t, rndPos.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntLength)
	rndPosRP := common.GetRandomPositiveRelativelyPrimeInt(rnd)
	assert.NotZero(t, rndPosRP, "rand int should not be zero")
	assert.True(t, common.IsNumberInMultiplicativeGroup(rnd, rndPosRP))
	assert.True(t, rndPosRP.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
	// TODO test for relative primeness
}

func TestGetRandomPrimeInt(t *testing.T) {
	prime := common.GetRandomPrimeInt(randomIntLength)
	assert.NotZero(t, prime, "rand prime should not be zero")
	assert.True(t, prime.ProbablyPrime(50), "rand prime should be prime")
}
