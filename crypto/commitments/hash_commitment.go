// partly ported from:
// https://github.com/KZen-networks/curv/blob/78a70f43f5eda376e5888ce33aec18962f572bbe/src/cryptographic_primitives/commitments/hash_commitment.rs

package commitments

import (
	"math/big"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

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

func NewHashCommitment(secrets ...*big.Int) (cmt *HashCommitDecommit, err error) {
	cmt = &HashCommitDecommit{}

	// r
	security := random.MustGetRandomInt(HashLength)

	// TODO revise use of legacy keccak256 which uses non-standard padding
	keccak256 := sha3.NewLegacyKeccak256()

	_, err = keccak256.Write(security.Bytes())
	if err != nil {
		return
	}

	for _, secret := range secrets {
		_, err = keccak256.Write(secret.Bytes())
		if err != nil {
			return
		}
	}
	digestKeccak256 := keccak256.Sum(nil)

	sha3256 := sha3.New256()
	_, err = sha3256.Write(digestKeccak256)
	if err != nil {
		return
	}

	digest := sha3256.Sum(nil)
	D := []*big.Int{security}
	D = append(D, secrets...)
	cmt.C = new(big.Int).SetBytes(digest)
	cmt.D = D

	return cmt, nil
}

func (cmt *HashCommitDecommit) Verify() (bool, error) {
	C, D := cmt.C, cmt.D

	// TODO revise use of legacy keccak256 which uses non-standard padding
	keccak256 := sha3.NewLegacyKeccak256()
	for _, secret := range D {
		_, err := keccak256.Write(secret.Bytes())
		if err != nil {
			return false, err
		}
	}
	digestKeccak256 := keccak256.Sum(nil)

	sha3256 := sha3.New256()
	_, err := sha3256.Write(digestKeccak256)
	if err != nil {
		return false, err
	}
	computeDigest := sha3256.Sum(nil)

	computeDigestBigInt := new(big.Int).SetBytes(computeDigest)

	if computeDigestBigInt.Cmp(C) == 0 {
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
