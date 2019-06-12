package random_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/binance-chain/tss-lib/common/random"
)

const (
	randomIntLength = 1024
)

func TestGetRandomInt(t *testing.T) {
	rnd := MustGetRandomInt(randomIntLength)
	assert.NotZero(t, rnd, "rand int should not be zero")
}

func TestGetRandomPositiveInt(t *testing.T) {
	rnd := MustGetRandomInt(randomIntLength)
	rndPos := GetRandomPositiveInt(rnd)
	assert.NotZero(t, rndPos, "rand int should not be zero")
	assert.True(t, rndPos.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	rnd := MustGetRandomInt(randomIntLength)
	rndPosRP := GetRandomPositiveRelativelyPrimeInt(rnd)
	assert.NotZero(t, rndPosRP, "rand int should not be zero")
	assert.True(t, IsNumberInMultiplicativeGroup(rnd, rndPosRP))
	assert.True(t, rndPosRP.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
	// TODO test for relative primeness
}

func TestGetRandomPrimeInt(t *testing.T) {
	prime := GetRandomPrimeInt(randomIntLength)
	assert.NotZero(t, prime, "rand prime should not be zero")
	assert.True(t, prime.ProbablyPrime(50), "rand prime should be prime")
}
