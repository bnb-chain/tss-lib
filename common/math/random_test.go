package math_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/math"
)

const (
	randomIntLength = 1024
)

func TestGetRandomInt(t *testing.T) {
	rnd := math.MustGetRandomInt(randomIntLength)
	assert.NotZero(t, rnd, "rand int should not be zero")
}

func TestGetRandomPositiveInt(t *testing.T) {
	rnd := math.MustGetRandomInt(randomIntLength)
	rndPos := math.GetRandomPositiveInt(rnd)
	assert.NotZero(t, rndPos, "rand int should not be zero")
	assert.True(t, rndPos.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPositiveIntStar(t *testing.T) {
	rnd := math.MustGetRandomInt(randomIntLength)
	rndPosStar := math.GetRandomPositiveIntStar(rnd)
	assert.NotZero(t, rndPosStar, "rand int should not be zero")
	assert.True(t, rndPosStar.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPrimeInt(t *testing.T) {
	prime := math.GetRandomPrimeInt(randomIntLength)
	assert.NotZero(t, prime, "rand int should not be zero")
}
