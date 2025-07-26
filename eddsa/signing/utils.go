// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"io"
	"math/big"

	"filippo.io/edwards25519"
)

func encodedBytesToBigInt(s *[32]byte) *big.Int {
	// Use a copy so we don't screw up our original
	// memory.
	sCopy := new([32]byte)
	for i := 0; i < 32; i++ {
		sCopy[i] = s[i]
	}
	reverse(sCopy)

	bi := new(big.Int).SetBytes(sCopy[:])

	return bi
}

func bigIntToEncodedBytes(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s
	}

	// Caveat: a can be longer than 32 bytes.
	s = copyBytes(a.Bytes())

	// Reverse the byte string --> little endian after
	// encoding.
	reverse(s)

	return s
}

func copyBytes(aB []byte) *[32]byte {
	if aB == nil {
		return nil
	}
	s := new([32]byte)

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < 32 {
		diff := 32 - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < 32; i++ {
		s[i] = aB[i]
	}

	return s
}

func ecPointToEncodedBytes(x *big.Int, y *big.Int) *[32]byte {
	s := bigIntToEncodedBytes(y)
	xB := bigIntToEncodedBytes(x)

	xP, err := new(edwards25519.Point).SetBytes(xB[:])
	if err != nil {
		return nil
	}
	isNegative := xP.Equal(edwards25519.NewIdentityPoint()) == 0 && (xB[31]>>7) == 1

	if isNegative {
		s[31] |= (1 << 7)
	} else {
		s[31] &^= (1 << 7)
	}

	return s
}

func reverse(s *[32]byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func addExtendedElements(p, q *edwards25519.Point) *edwards25519.Point {
	return new(edwards25519.Point).Add(p, q)
}

func ecPointToExtendedElement(ec elliptic.Curve, x *big.Int, y *big.Int, rand io.Reader) *edwards25519.Point {
	p, err := ecXYToPoint(x, y)
	if err != nil {
		return nil
	}
	return p
}

// X, YからEd25519圧縮形式のPointを生成する
func ecXYToPoint(x, y *big.Int) (*edwards25519.Point, error) {
	yBytes := bigIntToEncodedBytes(y)
	// Xの符号ビットをセット
	if x.Bit(0) == 1 {
		yBytes[31] |= 0x80
	} else {
		yBytes[31] &^= 0x80
	}

	return new(edwards25519.Point).SetBytes(yBytes[:])
}
