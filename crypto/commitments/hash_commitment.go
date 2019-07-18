// partly ported from:
// https://github.com/KZen-networks/curv/blob/78a70f43f5eda376e5888ce33aec18962f572bbe/src/cryptographic_primitives/commitments/hash_commitment.rs

package commitments

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
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

func NewHashCommitment(secrets ...*big.Int) *HashCommitDecommit {
	security := random.MustGetRandomInt(HashLength) // r

	parts := make([]*big.Int, len(secrets) + 1)
	parts[0] = security
	for i := 1; i < len(parts); i++ {
		parts[i] = secrets[i - 1]
	}
	hash := common.SHA512_256i(parts...)

	cmt := &HashCommitDecommit{}
	cmt.C = hash
	cmt.D = parts
	return cmt
}

func (cmt *HashCommitDecommit) Verify() bool {
	C, D := cmt.C, cmt.D
	if C == nil || D == nil {
		return false
	}
	hash := common.SHA512_256i(D...)
	if hash.Cmp(C) == 0 {
		return true
	} else {
		return false
	}
}

func (cmt *HashCommitDecommit) DeCommit() (bool, HashDeCommitment) {
	if cmt.Verify() {
		// [1:] skips random element r in D
		return true, cmt.D[1:]
	} else {
		return false, nil
	}
}
