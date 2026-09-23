// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package vss_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	. "github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

func TestCheckIndexesDup(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, indexes[99])
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCheckIndexesZero(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, tss.EC().Params().N)
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCreate(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	vs, _, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
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

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	vs, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(tss.EC(), threshold, vs))
	}
}

func TestVerifyRejectsZeroShare(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	ids := make([]*big.Int, 0, num)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	vs, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	badShare := &Share{
		Threshold: shares[0].Threshold,
		ID:        shares[0].ID,
		Share:     big.NewInt(0),
	}
	assert.NotPanics(t, func() {
		assert.False(t, badShare.Verify(tss.EC(), threshold, vs))
	})
}

func TestCreateRejectsMalformedInputs(t *testing.T) {
	q := tss.EC().Params().N
	secret := common.GetRandomPositiveInt(rand.Reader, q)
	ids := []*big.Int{
		common.GetRandomPositiveInt(rand.Reader, q),
		common.GetRandomPositiveInt(rand.Reader, q),
		common.GetRandomPositiveInt(rand.Reader, q),
	}

	t.Run("nil ec", func(tt *testing.T) {
		_, _, err := Create(nil, 1, secret, ids, rand.Reader)
		assert.Error(tt, err)
	})
	t.Run("nil rand", func(tt *testing.T) {
		_, _, err := Create(tss.EC(), 1, secret, ids, nil)
		assert.Error(tt, err)
	})
	t.Run("num == threshold (boundary)", func(tt *testing.T) {
		// 3 shares for degree-3 polynomial: too few to reconstruct
		// (need ≥ threshold+1). Old `num < threshold` admitted this.
		_, _, err := Create(tss.EC(), 3, secret, ids, rand.Reader)
		assert.Error(tt, err)
		assert.Equal(tt, ErrNumSharesBelowThreshold, err)
	})
	t.Run("num == threshold+1 (minimum honest)", func(tt *testing.T) {
		_, _, err := Create(tss.EC(), 2, secret, ids, rand.Reader)
		assert.NoError(tt, err)
	})
}

func TestVerifyRejectsCurveMismatch(t *testing.T) {
	num, threshold := 5, 3
	q := tss.EC().Params().N
	secret := common.GetRandomPositiveInt(rand.Reader, q)
	ids := make([]*big.Int, 0, num)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, q))
	}
	vs, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	// Reassign vs[0] to a copy whose stored curve is Edwards rather
	// than secp256k1; coords are unchanged. The earlier SetCurve
	// behavior would have silently re-attached secp256k1 and proceeded
	// with the on-curve check. The new SameCurve gate rejects up-front.
	mismatched := crypto.NewECPointNoCurveCheck(tss.Edwards(), vs[0].X(), vs[0].Y())
	tampered := make(Vs, len(vs))
	copy(tampered, vs)
	tampered[0] = mismatched
	assert.False(t, shares[0].Verify(tss.EC(), threshold, tampered))
}

func TestReConstructRejectsMalformedInputs(t *testing.T) {
	num, threshold := 5, 3
	q := tss.EC().Params().N
	secret := common.GetRandomPositiveInt(rand.Reader, q)
	ids := make([]*big.Int, 0, num)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, q))
	}
	_, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	t.Run("nil ec", func(tt *testing.T) {
		_, err := shares[:threshold+1].ReConstruct(nil)
		assert.Error(tt, err)
	})
	t.Run("empty shares", func(tt *testing.T) {
		_, err := Shares{}.ReConstruct(tss.EC())
		assert.Error(tt, err)
		assert.Equal(tt, ErrNumSharesBelowThreshold, err)
	})
	t.Run("nil share element", func(tt *testing.T) {
		bad := make(Shares, threshold+1)
		copy(bad, shares[:threshold+1])
		bad[1] = nil
		_, err := bad.ReConstruct(tss.EC())
		assert.Error(tt, err)
	})
	t.Run("mixed threshold", func(tt *testing.T) {
		bad := make(Shares, threshold+1)
		copy(bad, shares[:threshold+1])
		bad[1] = &Share{Threshold: threshold + 99, ID: shares[1].ID, Share: shares[1].Share}
		_, err := bad.ReConstruct(tss.EC())
		assert.Error(tt, err)
	})
	t.Run("mod-q ID collision (k vs k+q)", func(tt *testing.T) {
		// Forge a share whose raw ID = honest_id + q. Lagrange code
		// would compute (k+q) - k = q ≡ 0 mod q, then ModInverse(0, q)
		// = nil, then panic on the next Mul. The new sub.Sign() == 0
		// guard returns a clean error instead.
		bad := make(Shares, threshold+1)
		copy(bad, shares[:threshold+1])
		bad[1] = &Share{
			Threshold: shares[1].Threshold,
			ID:        new(big.Int).Add(shares[0].ID, q),
			Share:     shares[1].Share,
		}
		assert.NotPanics(tt, func() {
			_, err := bad.ReConstruct(tss.EC())
			assert.Error(tt, err)
			assert.Contains(tt, err.Error(), "collide mod q")
		})
	})
}

func TestReconstruct(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	_, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold].ReConstruct(tss.EC())
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold+1].ReConstruct(tss.EC())
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)
	assert.Zero(t, secret.Cmp(secret3))

	secret4, err4 := shares[:num].ReConstruct(tss.EC())
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
	assert.Zero(t, secret.Cmp(secret4))
}
