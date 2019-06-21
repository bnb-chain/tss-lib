package vss_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/random"
	. "github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

func TestCreate(t *testing.T) {
	num, threshold := 3, 2

	secret := random.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, random.GetRandomPositiveInt(tss.EC().Params().N))
	}

	polyGs, _, err := Create(threshold, secret, ids)
	assert.Nil(t, err)

	assert.Equal(t, threshold, len(polyGs.PolyG))
	// assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold, len(polyGs.PolyG))

	// ensure that each polyGs has two points on the curve
	for i, pg := range polyGs.PolyG {
		assert.NotZero(t, pg.X())
		assert.NotZero(t, pg.Y())
		assert.True(t, pg.IsOnCurve())
		assert.NotZero(t, polyGs.PolyG[i].X())
		assert.NotZero(t, polyGs.PolyG[i].Y())
	}
}

func TestVerify(t *testing.T) {
	num, threshold := 3, 2

	secret := random.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, random.GetRandomPositiveInt(tss.EC().Params().N))
	}

	polyGs, shares, err := Create(threshold, secret, ids)
	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(threshold, polyGs.PolyG))
	}
}

func TestReconstruct(t *testing.T) {
	num, threshold := 3, 2

	secret := random.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, random.GetRandomPositiveInt(tss.EC().Params().N))
	}

	_, shares, err := Create(threshold, secret, ids)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold-1].ReConstruct()
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold].ReConstruct()
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)

	secret4, err4 := shares[:num].ReConstruct()
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
}
