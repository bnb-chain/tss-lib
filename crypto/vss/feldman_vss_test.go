package vss_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"tss-lib/common/math"
	"tss-lib/crypto/vss"
)

func TestCreate(t *testing.T) {
	num, threshold := 3, 2

	secret := math.GetRandomPositiveInt(vss.EC.N)
	t.Log(secret)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, math.GetRandomPositiveInt(vss.EC.N))
	}

	params, polyG, poly, shares, err := vss.Create(threshold, num, ids, secret)
	assert.Nil(t, err)

	assert.Equal(t, threshold, params.Threshold)
	assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold, len(poly.Poly))
	assert.Equal(t, threshold, len(polyG.PolyG))

	// coefs must not be zero
	for i := range poly.Poly {
		assert.NotZero(t, poly.Poly[i])
	}

	// ensure that each polyG len() == 2
	for i := range polyG.PolyG {
		assert.Equal(t, len(polyG.PolyG[i]), 2)
		assert.NotZero(t, polyG.PolyG[i][0])
		assert.NotZero(t, polyG.PolyG[i][1])
	}

	t.Log(polyG)
	t.Log(poly)
	t.Log(shares)
}

func TestVerify(t *testing.T) {
	num, threshold := 3, 2

	secret := math.GetRandomPositiveInt(vss.EC.N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, math.GetRandomPositiveInt(vss.EC.N))
	}

	_, polyG, _, shares, err := vss.Create(threshold, num, ids, secret)
	assert.Nil(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(polyG))
	}
}

func TestCombine(t *testing.T) {
	num, threshold := 3, 2

	secret := math.GetRandomPositiveInt(vss.EC.N)
	t.Log(secret)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, math.GetRandomPositiveInt(vss.EC.N))
	}

	_, _, _, shares, err := vss.Create(threshold, num, ids, secret)
	assert.Nil(t, err)

	secret2, err2 := vss.Combine(shares[:threshold-1])
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	t.Log(err2)
	t.Log(secret2)

	secret3, err3 := vss.Combine(shares[:threshold])
	assert.Nil(t, err3)
	t.Log(err3)
	t.Log(secret3)

	secret4, err4 := vss.Combine(shares[:num])
	assert.Nil(t, err4)
	t.Log(err4)
	t.Log(secret4)
}
