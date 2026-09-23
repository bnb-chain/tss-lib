// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"

	. "github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

func TestFlattenECPoints(t *testing.T) {
	type args struct {
		in []*ECPoint
	}
	tests := []struct {
		name    string
		args    args
		want    []*big.Int
		wantErr bool
	}{{
		name: "flatten with 2 points (happy)",
		args: args{[]*ECPoint{
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(2)),
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(3), big.NewInt(4)),
		}},
		want: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)},
	}, {
		name: "flatten with nil point (expects err)",
		args: args{[]*ECPoint{
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(2)),
			nil,
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(3), big.NewInt(4))},
		},
		want:    nil,
		wantErr: true,
	}, {
		name: "flatten with nil coordinate (expects err)",
		args: args{[]*ECPoint{
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(2)),
			NewECPointNoCurveCheck(tss.EC(), nil, big.NewInt(4))},
		},
		want:    nil,
		wantErr: true,
	}, {
		name:    "flatten with nil `in` slice",
		args:    args{nil},
		want:    nil,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FlattenECPoints(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("FlattenECPoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FlattenECPoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnFlattenECPoints(t *testing.T) {
	type args struct {
		in []*big.Int
	}
	tests := []struct {
		name    string
		args    args
		want    []*ECPoint
		wantErr bool
	}{{
		name: "un-flatten 2 points (happy)",
		args: args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}},
		want: []*ECPoint{
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(2)),
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(3), big.NewInt(4)),
		},
	}, {
		name:    "un-flatten uneven len(points) (expects err)",
		args:    args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}},
		want:    nil,
		wantErr: true,
	}, {
		name:    "un-flatten with nil coordinate (expects err)",
		args:    args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), nil}},
		want:    nil,
		wantErr: true,
	}, {
		name:    "flatten with nil `in` slice",
		args:    args{nil},
		want:    nil,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnFlattenECPoints(tss.EC(), tt.args.in, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnFlattenECPoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnFlattenECPoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsIdentityAndValidateBasic(t *testing.T) {
	edw := edwards.Edwards()
	tss.RegisterCurve("ed25519", edw)
	t.Run("Edwards identity (0,1)", func(tt *testing.T) {
		p := NewECPointNoCurveCheck(edw, big.NewInt(0), big.NewInt(1))
		assert.True(tt, p.IsOnCurve(), "Edwards (0,1) is on-curve")
		assert.True(tt, p.IsIdentity())
		assert.False(tt, p.ValidateBasic(), "ValidateBasic must reject identity")
	})
	t.Run("Edwards non-identity passes", func(tt *testing.T) {
		k := big.NewInt(7)
		x, y := edw.ScalarBaseMult(k.Bytes())
		p := NewECPointNoCurveCheck(edw, x, y)
		assert.False(tt, p.IsIdentity())
		assert.True(tt, p.ValidateBasic())
	})
	t.Run("zero coord (0,0) rejected as identity even if reachable", func(tt *testing.T) {
		p := NewECPointNoCurveCheck(edw, big.NewInt(0), big.NewInt(0))
		assert.True(tt, p.IsIdentity())
		assert.False(tt, p.ValidateBasic())
	})
	t.Run("nil coords", func(tt *testing.T) {
		var p *ECPoint
		assert.False(tt, p.IsIdentity())
		assert.False(tt, p.ValidateBasic())
	})
}

func TestValidateInSubgroup(t *testing.T) {
	edw := edwards.Edwards()
	tss.RegisterCurve("ed25519", edw)
	s256 := tss.S256()
	tss.RegisterCurve("secp256k1", s256)

	t.Run("Edwards prime-order point passes", func(tt *testing.T) {
		x, y := edw.ScalarBaseMult(big.NewInt(7).Bytes())
		p := NewECPointNoCurveCheck(edw, x, y)
		assert.True(tt, p.IsInPrimeOrderSubgroup())
		assert.True(tt, p.ValidateInSubgroup())
	})
	t.Run("Edwards identity rejected by ValidateBasic before subgroup check", func(tt *testing.T) {
		p := NewECPointNoCurveCheck(edw, big.NewInt(0), big.NewInt(1))
		assert.True(tt, p.IsIdentity())
		assert.False(tt, p.ValidateInSubgroup(), "identity should fail ValidateBasic gate")
		assert.True(tt, p.IsInPrimeOrderSubgroup(), "[N]·identity == identity, so the raw subgroup query still returns true; the rejection comes from ValidateBasic")
	})
	t.Run("Edwards low-order point rejected", func(tt *testing.T) {
		// (0, -1 mod p) is the order-2 point on Ed25519 (it negates to itself
		// under the curve's point negation). Construct it explicitly.
		p := edw.Params().P
		minusOne := new(big.Int).Sub(p, big.NewInt(1))
		lowOrder := NewECPointNoCurveCheck(edw, big.NewInt(0), minusOne)
		assert.True(tt, lowOrder.IsOnCurve(), "sanity: (0, p-1) is on Ed25519")
		assert.False(tt, lowOrder.IsIdentity())
		assert.False(tt, lowOrder.IsInPrimeOrderSubgroup(), "order-2 point not in prime-order subgroup")
		assert.False(tt, lowOrder.ValidateInSubgroup())
	})
	t.Run("secp256k1 on-curve point passes (cofactor 1)", func(tt *testing.T) {
		x, y := s256.ScalarBaseMult(big.NewInt(42).Bytes())
		p := NewECPointNoCurveCheck(s256, x, y)
		assert.True(tt, p.ValidateInSubgroup())
	})
}

func TestS256EcpointJsonSerialization(t *testing.T) {
	ec := btcec.S256()
	tss.RegisterCurve("secp256k1", ec)

	pubKeyBytes, err := hex.DecodeString("03935336acb03b2b801d8f8ac5e92c56c4f6e93319901fdfffba9d340a874e2879")
	assert.NoError(t, err)
	pbk, err := btcec.ParsePubKey(pubKeyBytes)
	assert.NoError(t, err)

	point, err := NewECPoint(ec, pbk.X(), pbk.Y())
	assert.NoError(t, err)
	bz, err := json.Marshal(point)
	assert.NoError(t, err)
	assert.True(t, len(bz) > 0)

	var umpoint ECPoint
	err = json.Unmarshal(bz, &umpoint)
	assert.NoError(t, err)

	assert.True(t, point.Equals(&umpoint))
	assert.True(t, reflect.TypeOf(point.Curve()) == reflect.TypeOf(umpoint.Curve()))
}

func TestEdwardsEcpointJsonSerialization(t *testing.T) {
	ec := edwards.Edwards()
	tss.RegisterCurve("ed25519", ec)

	pubKeyBytes, err := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f249")
	assert.NoError(t, err)
	pbk, err := edwards.ParsePubKey(pubKeyBytes)
	assert.NoError(t, err)

	point, err := NewECPoint(ec, pbk.X, pbk.Y)
	assert.NoError(t, err)
	bz, err := json.Marshal(point)
	assert.NoError(t, err)
	assert.True(t, len(bz) > 0)

	var umpoint ECPoint
	err = json.Unmarshal(bz, &umpoint)
	assert.NoError(t, err)

	assert.True(t, point.Equals(&umpoint))
	assert.True(t, reflect.TypeOf(point.Curve()) == reflect.TypeOf(umpoint.Curve()))
}
