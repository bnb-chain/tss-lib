// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"errors"
	"reflect"

	s256k1 "github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

type CurveName string

const (
	Secp256k1 CurveName = "secp256k1"
	Ed25519   CurveName = "ed25519"
)

var (
	ec       elliptic.Curve
	registry map[CurveName]elliptic.Curve
)

// Init default curve (secp256k1)
func init() {
	ec = s256k1.S256()

	registry = make(map[CurveName]elliptic.Curve)
	registry[Secp256k1] = s256k1.S256()
	registry[Ed25519] = edwards.Edwards()
}

func RegisterCurve(name CurveName, curve elliptic.Curve) {
	registry[name] = curve
}

// return curve, exist(bool)
func GetCurveByName(name CurveName) (elliptic.Curve, bool) {
	if val, exist := registry[name]; exist {
		return val, true
	}

	return nil, false
}

// return name, exist(bool)
func GetCurveName(curve elliptic.Curve) (CurveName, bool) {
	for name, e := range registry {
		if reflect.TypeOf(curve) == reflect.TypeOf(e) {
			return name, true
		}
	}

	return "", false
}

// EC returns the current elliptic curve in use. The default is secp256k1
func EC() elliptic.Curve {
	return ec
}

// SetCurve sets the curve used by TSS. Must be called before Start. The default is secp256k1
// Deprecated
func SetCurve(curve elliptic.Curve) {
	if curve == nil {
		panic(errors.New("SetCurve received a nil curve"))
	}
	ec = curve
}

// secp256k1
func S256() elliptic.Curve {
	return s256k1.S256()
}

func Edwards() elliptic.Curve {
	return edwards.Edwards()
}
