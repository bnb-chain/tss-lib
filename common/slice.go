// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

func BigIntsToBytes(bigInts []*big.Int) [][]byte {
	bzs := make([][]byte, len(bigInts))
	for i := range bzs {
		if bigInts[i] == nil {
			continue
		}
		bzs[i] = bigInts[i].Bytes()
	}
	return bzs
}

func MultiBytesToBigInts(bytes [][]byte) []*big.Int {
	ints := make([]*big.Int, len(bytes))
	for i := range ints {
		ints[i] = new(big.Int).SetBytes(bytes[i])
	}
	return ints
}

// Returns true when the byte slice is non-nil and non-empty
func NonEmptyBytes(bz []byte) bool {
	return bz != nil && 0 < len(bz)
}

// Returns true when all of the slices in the multi-dimensional byte slice are non-nil and non-empty
func NonEmptyMultiBytes(bzs [][]byte, expectLen ...int) bool {
	if len(bzs) == 0 {
		return false
	}
	// variadic (optional) arg test
	if 0 < len(expectLen) && expectLen[0] != len(bzs) {
		return false
	}
	for _, bz := range bzs {
		if !NonEmptyBytes(bz) {
			return false
		}
	}
	return true
}
