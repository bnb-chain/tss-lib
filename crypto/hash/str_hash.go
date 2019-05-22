package hash

import (
	"math/big"

	"golang.org/x/crypto/sha3"
)

func StrHash(id string) *big.Int {
	// hash 1 - keccak256
	keccak256 := sha3.NewLegacyKeccak256()
	keccak256.Write([]byte(id))

	digestKeccak256 := keccak256.Sum(nil)

	// hash 2 - sha3-256
	sha3256 := sha3.New256()
	sha3256.Write(digestKeccak256)

	// convert the hash ([]byte) to big.Int
	digest := sha3256.Sum(nil)
	return new(big.Int).SetBytes(digest)
}
