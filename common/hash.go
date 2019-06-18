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
	for _, bz := range in {
		if _, err := state.Write(bz); err != nil {
			return nil, err
		}
	}
	return state.Sum(nil), nil
}

func SHA512_256i(in... *big.Int) (*big.Int, error) {
	state := crypto.SHA512_256.New()
	for _, int := range in {
		if _, err := state.Write(int.Bytes()); err != nil {
			return nil, err
		}
	}
	return new(big.Int).SetBytes(state.Sum(nil)), nil
}
