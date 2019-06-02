package vss_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/math"
	. "github.com/binance-chain/tss-lib/crypto/vss"
)

func TestCreate(t *testing.T) {
	num, threshold := 3, 2

	secret := math.GetRandomPositiveInt(EC().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, math.GetRandomPositiveInt(EC().N))
	}

	params, polyGs, _, err := Create(threshold, secret, ids)
	assert.Nil(t, err)

	assert.Equal(t, threshold, params.Threshold)
	assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold, len(polyGs.PolyG))

	// ensure that each polyGs len() == 2 and non-zero
	for i := range polyGs.PolyG {
		assert.Equal(t, threshold, len(polyGs.PolyG[i]))
		assert.NotZero(t, polyGs.PolyG[i][0])
		assert.NotZero(t, polyGs.PolyG[i][1])
	}
}

func TestVerify(t *testing.T) {
	num, threshold := 3, 2

	secret := math.GetRandomPositiveInt(EC().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, math.GetRandomPositiveInt(EC().N))
	}

	_, polyGs, shares, err := Create(threshold, secret, ids)
	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(polyGs))
	}
}

func TestCombine(t *testing.T) {
	num, threshold := 3, 2

	secret := math.GetRandomPositiveInt(EC().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, math.GetRandomPositiveInt(EC().N))
	}

	_, _, shares, err := Create(threshold, secret, ids)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold-1].Combine()
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold].Combine()
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)

	secret4, err4 := shares[:num].Combine()
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
}
