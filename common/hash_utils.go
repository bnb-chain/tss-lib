// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"crypto/sha256"
	"math/big"
)

// RejectionSample implements the rejection sampling logic for converting a
// SHA512/256 hash to a value between 0-q
func RejectionSample(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	auxiliary := new(big.Int).Set(eHash)
	e := new(big.Int).Set(q)
	qBytesLen := len(q.Bytes())
	if qBytesLen > 32 {
		panic("invalid q size")
	}
	one := new(big.Int).SetInt64(1)
	for e.Cmp(q) != -1 {
		eHashAdded := auxiliary.Add(auxiliary, one)
		eHashReSample := sha256.Sum256(eHashAdded.Bytes())
		// sample qBytesLen bytes
		e = new(big.Int).SetBytes(eHashReSample[:qBytesLen])
	}
	return e
}
