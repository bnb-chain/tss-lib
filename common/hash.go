package common

import (
	"crypto"
	_ "crypto/sha512"
	"math/big"
)

const (
	hashInputDelimiter = byte('$')
)

// SHA-512/256 is protected against length extension attacks and is more performant than SHA-256 on 64-bit architectures.
// https://en.wikipedia.org/wiki/Template:Comparison_of_SHA_functions
func SHA512_256(in ...[]byte) []byte {
	var data []byte
	state := crypto.SHA512_256.New()
	inLen := len(in)
	if inLen == 0 {
		return nil
	}
	if bzSize := 0; inLen > 1 {
		for _, bz := range in {
			bzSize += len(bz)
		}
		data = make([]byte, 0, bzSize + inLen)
		for _, bz := range in {
			data = append(data, bz...)
			data = append(data, hashInputDelimiter) // safety delimiter
		}
	} else {
		data = in[0][:]
	}
	if _, err := state.Write(data); err != nil {
		// this should never happen. see: https://golang.org/pkg/hash/#Hash
		Logger.Errorf("SHA512_256 Write() failed unexpectedly: %v", err)
		return nil
	}
	return state.Sum(nil)
}

func SHA512_256i(in ...*big.Int) *big.Int {
	var data []byte
	state := crypto.SHA512_256.New()
	inLen := len(in)
	if inLen == 0 {
		return nil
	}
	if bzSize := 0; inLen > 1 {
		ptrs := make([][]byte, inLen)
		for i, int := range in {
			ptrs[i] = int.Bytes()
			bzSize += len(ptrs[i])
		}
		data = make([]byte, 0, bzSize + inLen)
		for i := range in {
			data = append(data, ptrs[i]...)
			data = append(data, hashInputDelimiter) // safety delimiter
		}
	} else {
		data = in[0].Bytes()
	}
	if _, err := state.Write(data); err != nil {
		// this should never happen. see: https://golang.org/pkg/hash/#Hash
		Logger.Errorf("SHA512_256i Write() failed unexpectedly: %v", err)
		return nil
	}
	return new(big.Int).SetBytes(state.Sum(nil))
}
