// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// partly ported from:
// https://github.com/KZen-networks/curv/blob/78a70f43f5eda376e5888ce33aec18962f572bbe/src/cryptographic_primitives/commitments/hash_commitment.rs

package commitments

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
)

const (
	HashLength = 256
)

type (
	HashCommitment   = *big.Int
	HashDeCommitment = []*big.Int

	HashCommitDecommit struct {
		C HashCommitment
		D HashDeCommitment
	}
)

func NewHashCommitmentWithRandomness(r *big.Int, secrets ...*big.Int) *HashCommitDecommit {
	parts := make([]*big.Int, len(secrets)+1)
	parts[0] = r
	for i := 1; i < len(parts); i++ {
		parts[i] = secrets[i-1]
	}
	hash := common.SHA512_256i(parts...)

	cmt := &HashCommitDecommit{}
	cmt.C = hash
	cmt.D = parts
	return cmt
}

func NewHashCommitment(secrets ...*big.Int) *HashCommitDecommit {
	r := common.MustGetRandomInt(HashLength) // r
	return NewHashCommitmentWithRandomness(r, secrets...)
}

func NewHashDeCommitmentFromBytes(marshalled [][]byte) HashDeCommitment {
	return common.MultiBytesToBigInts(marshalled)
}

func (cmt *HashCommitDecommit) Verify() bool {
	C, D := cmt.C, cmt.D
	if C == nil || D == nil {
		return false
	}
	hash := common.SHA512_256i(D...)
	return hash.Cmp(C) == 0
}

func (cmt *HashCommitDecommit) DeCommit() (bool, HashDeCommitment) {
	if cmt.Verify() {
		// [1:] skips random element r in D
		return true, cmt.D[1:]
	} else {
		return false, nil
	}
}
