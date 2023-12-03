// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto_test

import (

	"crypto/elliptic"

	"encoding/hex"
	"encoding/json"

	"math/big"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"

	. "github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/tss"
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


func TestAddECPoints(t *testing.T) {

	curveList := []*elliptic.CurveParams{elliptic.P224().Params(), elliptic.P256().Params(), elliptic.P384().Params()}

	// Check 2 + (N-2) = identity element, where N is the order of a given elliptic curve group
	for i := 0; i < len(curveList); i++ {
		minus2 := big.NewInt(-2)
		ECPoint1 := ScalarBaseMult(curveList[i], new(big.Int).Mod(minus2, curveList[i].N))
		ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(2))

		result, err := ECPoint1.Add(ECPoint2)

		if err != nil {
			t.Errorf("Add() error = %v", err)
		}

		if result.X() != nil || result.Y() != nil {
			t.Errorf("Add() expect = nil,nil, got X = %v, Y=%v", result.X(), result.Y())
		}
	}

	// Check identity + 5566*G = 5566G
	for i := 0; i < len(curveList); i++ {
		ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(0))
		ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(5566))

		result, err := ECPoint1.Add(ECPoint2)

		if err != nil {
			t.Errorf("Add() error = %v", err)
		}

		expect := ScalarBaseMult(curveList[i], big.NewInt(5566))

		if result.X().Cmp(expect.X()) != 0 || result.Y().Cmp(expect.Y()) != 0 {
			t.Errorf("Add() error = Two points not the same, result X = %v, Y=%v, expect X = %v, Y=%v", result.X(), result.Y(), expect.X(), expect.Y())
		}
	}

	// Check 5566*G + identity = 5566G
	for i := 0; i < len(curveList); i++ {
		ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5566))
		ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(0))

		result, err := ECPoint1.Add(ECPoint2)

		if err != nil {
			t.Errorf("Add() error = %v", err)
		}

		expect := ScalarBaseMult(curveList[i], big.NewInt(5566))

		if result.X().Cmp(expect.X()) != 0 || result.Y().Cmp(expect.Y()) != 0 {
			t.Errorf("Add() error = Two points not the same, result X = %v, Y=%v, expect X = %v, Y=%v", result.X(), result.Y(), expect.X(), expect.Y())
		}
	}

	// Check 5*G +5*G = 10*G
	for i := 0; i < len(curveList); i++ {
		ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5))
		ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(5))

		result, err := ECPoint1.Add(ECPoint2)

		if err != nil {
			t.Errorf("Add() error = %v", err)
		}

		expect := ScalarBaseMult(curveList[i], big.NewInt(10))

		if result.X().Cmp(expect.X()) != 0 || result.Y().Cmp(expect.Y()) != 0 {
			t.Errorf("Add() error = Two points not the same, result X = %v, Y=%v, expect X = %v, Y=%v", result.X(), result.Y(), expect.X(), expect.Y())
		}
	}
}

func TestScalarMult(t *testing.T) {
	curveList := []*elliptic.CurveParams{elliptic.P224().Params(), elliptic.P256().Params(), elliptic.P384().Params()}

	for i := 0; i < len(curveList); i++ {
		ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5))
		result := ECPoint1.ScalarMult(curveList[i].N)

		if result.X() != nil || result.Y() != nil {
			t.Errorf("Add() expect = nil,nil, got X = %v, Y=%v", result.X(), result.Y())
		}
	}
}

func TestScalarBaseMult(t *testing.T) {
	curveList := []*elliptic.CurveParams{elliptic.P224().Params(), elliptic.P256().Params(), elliptic.P384().Params()}

	for i := 0; i < len(curveList); i++ {
		result := ScalarBaseMult(curveList[i], big.NewInt(0))

		if result.X() != nil || result.Y() != nil {
			t.Errorf("Add() expect = nil,nil, got X = %v, Y=%v", result.X(), result.Y())
		}
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
