// partly ported from:
// https://github.com/KZen-networks/curv/blob/78a70f43f5eda376e5888ce33aec18962f572bbe/src/cryptographic_primitives/commitments/hash_commitment.rs

package commitments

import (
	"crypto"
	"math/big"

	"github.com/pkg/errors"
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

func FlattenPointsForCommit(in [][]*big.Int) ([]*big.Int, error) {
	flat := make([]*big.Int, 0, len(in) * 2)
	for _, point := range in {
		if point[0] == nil || point[1] == nil {
			return nil, errors.New("FlattenPointsForCommit found nil coordinate")
		}
		flat = append(flat, point[0])
		flat = append(flat, point[1])
	}
	return flat, nil
}

func UnFlattenPointsAfterDecommit(in []*big.Int) ([][]*big.Int, error) {
	if len(in) % 2 != 0 {
		return nil, errors.New("UnFlattenPointsAfterDecommit expected an in len divisible by 2")
	}
	unFlat := make([][]*big.Int, len(in) / 2)
	for i, j := 0, 0; i < len(in); i, j = i + 2, j + 1 {
		unFlat[j] = []*big.Int{in[i], in[i + 1]}
	}
	for _, point := range unFlat {
		if point[0] == nil || point[1] == nil {
			return nil, errors.New("UnFlattenPointsAfterDecommit found nil coordinate after unpack")
		}
	}
	return unFlat, nil
}

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
