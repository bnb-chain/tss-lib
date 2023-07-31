// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"crypto/sha512"
	"math/big"
)

// RejectionSample implements the rejection sampling logic for converting a
// SHA512/256 hash to a value between 0-q
func RejectionSample(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	reSampleBytes := sha512.Sum512(append([]byte("RejectSample"), eHash.Bytes()...))
	eHashReSample := new(big.Int).SetBytes(reSampleBytes[:])
	e := eHashReSample.Mod(eHashReSample, q)
	return e
}
