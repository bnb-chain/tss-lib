// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package vss_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	. "github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

func TestCheckIndexesDup(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 10; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, big.NewInt(999))
	indexes = append(indexes, big.NewInt(999))
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCheckIndexesZero(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 10; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, tss.EC().Params().N)
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCreate(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	vs, _, err := Create(tss.EC(), threshold, secret, ids)
	assert.Nil(t, err)

	assert.Equal(t, threshold+1, len(vs))
	// assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold+1, len(vs))

	// ensure that each vs has two points on the curve
	for i, pg := range vs {
		assert.NotZero(t, pg.X())
		assert.NotZero(t, pg.Y())
		assert.True(t, pg.IsOnCurve())
		assert.NotZero(t, vs[i].X())
		assert.NotZero(t, vs[i].Y())
	}
}

func TestVerify(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	vs, shares, err := Create(tss.EC(), threshold, secret, ids)
	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(tss.EC(), threshold, vs))
	}
}

func TestReconstruct(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	_, shares, err := Create(tss.EC(), threshold, secret, ids)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold-1].ReConstruct(tss.EC())
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold].ReConstruct(tss.EC())
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)

	secret4, err4 := shares[:num].ReConstruct(tss.EC())
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
}
