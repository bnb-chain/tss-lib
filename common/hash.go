package common

import (
	"crypto"
	_ "crypto/sha512"
	"math/big"
)

// SHA-512/256 is protected against length extension attacks and is more performant than SHA-256 on 64-bit.
// https://en.wikipedia.org/wiki/Template:Comparison_of_SHA_functions
func SHA512_256(in... []byte) ([]byte, error) {
	state := crypto.SHA512_256.New()
	size := 0
	for _, bz := range in {
		size += len(bz)
	}
	data := make([]byte, 0, size)
	for _, bz := range in {
		data = append(data, bz...)
	}
	if _, err := state.Write(data); err != nil {
		return nil, err
	}
	return state.Sum(nil), nil
}

func SHA512_256i(in... *big.Int) (*big.Int, error) {
	state := crypto.SHA512_256.New()
	size := 0
	ptrs := make([][]byte, len(in))
	for i, int := range in {
		ptrs[i] = int.Bytes()
		size += len(ptrs[i])
	}
	data := make([]byte, 0, size)
	for i := range in {
		data = append(data, ptrs[i]...)
	}
	if _, err := state.Write(data); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(state.Sum(nil)), nil
}
