// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// modInt is a *big.Int that performs all of its arithmetic with modular reduction.
type modInt big.Int

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

func ModInt(mod *big.Int) *modInt {
	return (*modInt)(mod)
}

func (mi *modInt) Add(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Add(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Sub(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Sub(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Div(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Div(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Mul(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Exp(x, y *big.Int) *big.Int {
	return new(big.Int).Exp(x, y, mi.i())
}

func (mi *modInt) ModInverse(g *big.Int) *big.Int {
	return new(big.Int).ModInverse(g, mi.i())
}

func (mi *modInt) i() *big.Int {
	return (*big.Int)(mi)
}

func IsInInterval(b *big.Int, bound *big.Int) bool {
	return b.Cmp(bound) == -1 && b.Cmp(zero) >= 0
}

func AppendBigIntToBytesSlice(commonBytes []byte, appended *big.Int) []byte {
	resultBytes := make([]byte, len(commonBytes), len(commonBytes)+len(appended.Bytes()))
	copy(resultBytes, commonBytes)
	resultBytes = append(resultBytes, appended.Bytes()...)
	return resultBytes
}
