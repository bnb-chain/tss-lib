package common

import (
	"crypto"
	"math/big"

	_ "golang.org/x/crypto/sha3"
)

func SHA3_256(in... []byte) ([]byte, error) {
	sha3256 := crypto.SHA3_256.New()
	for _, bz := range in {
		_, err := sha3256.Write(bz)
		if err != nil {
			return nil, err
		}
	}
	return sha3256.Sum(nil), nil
}

func SHA3_256i(in... *big.Int) (*big.Int, error) {
	sha3256 := crypto.SHA3_256.New()
	for _, int := range in {
		_, err := sha3256.Write(int.Bytes())
		if err != nil {
			return nil, err
		}
	}
	return new(big.Int).SetBytes(sha3256.Sum(nil)), nil
}
