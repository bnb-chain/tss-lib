// ported from:
// https://github.com/KZen-networks/curv/blob/78a70f43f5eda376e5888ce33aec18962f572bbe/src/cryptographic_primitives/commitments/hash_commitment.rs

package commitments

import (
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/binance-chain/tss-lib/common/math"
)

const (
	HashLength = 256
)

type (
	HashCommitment   =   *big.Int
	HashDeCommitment = []*big.Int

	HashCommitDecommit struct {
		C  HashCommitment
		D  HashDeCommitment
	}
)

func NewHashCommitment(secrets ...*big.Int) (cmt *HashCommitDecommit, err error) {
	cmt = &HashCommitDecommit{}

	// Generate the random num
	rnd := math.MustGetRandomInt(HashLength)

	// TODO revise use of legacy keccak256 which uses non-standard padding
	keccak256 := sha3.NewLegacyKeccak256()

	_, err = keccak256.Write(rnd.Bytes())
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

	// second, hash with the SHA3-256
	sha3256 := sha3.New256()

	_, err = sha3256.Write(digestKeccak256)
	if err != nil {
		return
	}

	digest := sha3256.Sum(nil)

	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)

	D := []*big.Int{rnd}
	D = append(D, secrets...)

	cmt.C = digestBigInt
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
		return true, cmt.D[1:], nil
	} else {
		return false, nil, nil
	}
}
