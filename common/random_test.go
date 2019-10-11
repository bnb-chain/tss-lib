// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
)

const (
	randomIntBitLen = 1024
)

func TestGetRandomInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	assert.NotZero(t, rnd, "rand int should not be zero")
}

func TestGetRandomPositiveInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	rndPos := common.GetRandomPositiveInt(rnd)
	assert.NotZero(t, rndPos, "rand int should not be zero")
	assert.True(t, rndPos.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	rndPosRP := common.GetRandomPositiveRelativelyPrimeInt(rnd)
	assert.NotZero(t, rndPosRP, "rand int should not be zero")
	assert.True(t, common.IsNumberInMultiplicativeGroup(rnd, rndPosRP))
	assert.True(t, rndPosRP.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
	// TODO test for relative primeness
}

func TestGetRandomPrimeInt(t *testing.T) {
	prime := common.GetRandomPrimeInt(randomIntBitLen)
	assert.NotZero(t, prime, "rand prime should not be zero")
	assert.True(t, prime.ProbablyPrime(50), "rand prime should be prime")
}

func TestGetRandomSophieAndSafePrimes(t *testing.T) {
	sgp := common.GetRandomSophieGermainPrime(randomIntBitLen)
	t.Logf("p1: %+v", sgp.Prime())
	t.Logf("p2: %+v", sgp.SafePrime())
	assert.True(t, sgp.Validate())
}

func TestGetRandomSophieGermainPrimesConcurrent(t *testing.T) {
	sgps := common.GetRandomSophieGermainPrimesConcurrent(randomIntBitLen, 2, runtime.NumCPU())
	assert.NotNil(t, sgps)
	assert.Equal(t, 2, len(sgps))
	for _, sgp := range sgps {
		assert.NotNil(t, sgp)
		assert.True(t, sgp.Validate())
	}
}
