// partly ported from:
// https://github.com/KZen-networks/curv/blob/78a70f43f5eda376e5888ce33aec18962f572bbe/src/cryptographic_primitives/commitments/hash_commitment.rs

package commitments

import (
	"crypto"
	"math/big"

	_ "golang.org/x/crypto/sha3"

	"github.com/binance-chain/tss-lib/common/random"
)

const (
	HashLength = 256
)

type (
	HashCommitment   =   *big.Int
	HashDeCommitment = []*big.Int

	HashCommitDecommit struct {
		// TODO include 256-bit random component R in D, written to C digest
		C  HashCommitment
		D  HashDeCommitment
	}
)

func NewHashCommitment(secrets ...*big.Int) (*HashCommitDecommit, error) {
	security := random.MustGetRandomInt(HashLength) // r

	parts := make([]*big.Int, len(secrets) + 1)
	parts[0] = security
	for i := 1; i < len(parts); i++ {
		parts[i] = secrets[i - 1]
	}
	sha3256Sum, err := generateSHA3_256Digest(parts)
	if err != nil {
		return nil, err
	}

	cmt := &HashCommitDecommit{}
	cmt.C = new(big.Int).SetBytes(sha3256Sum)
	cmt.D = parts
	return cmt, nil
}

func (cmt *HashCommitDecommit) Verify() (bool, error) {
	C, D := cmt.C, cmt.D

	sha3256Sum, err := generateSHA3_256Digest(D)
	if err != nil {
		return false, err
	}
	sha3256SumInt := new(big.Int).SetBytes(sha3256Sum)

	if sha3256SumInt.Cmp(C) == 0 {
		return true, nil
	} else {
		return false, nil
	}
}

func (cmt *HashCommitDecommit) DeCommit() (bool, HashDeCommitment, error) {
	result, err := cmt.Verify()
	if err != nil {
		return false, nil, err
	}
	if result {
		// [1:] skips random element r in D
		return true, cmt.D[1:], nil
	} else {
		return false, nil, nil
	}
}

func generateSHA3_256Digest(in []*big.Int) ([]byte, error) {
	sha3256 := crypto.SHA3_256.New()
	for _, int := range in {
		_, err := sha3256.Write(int.Bytes())
		if err != nil {
			return nil, err
		}
	}
	return sha3256.Sum(nil), nil
}
