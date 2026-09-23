// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// partly ported from:
// https://github.com/KZen-networks/curv/blob/78a70f43f5eda376e5888ce33aec18962f572bbe/src/cryptographic_primitives/commitments/hash_commitment.rs

package commitments

import (
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
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

func NewHashCommitment(rand io.Reader, secrets ...*big.Int) *HashCommitDecommit {
	r := common.MustGetRandomInt(rand, HashLength) // r
	return NewHashCommitmentWithRandomness(r, secrets...)
}

func NewHashDeCommitmentFromBytes(marshalled [][]byte) HashDeCommitment {
	return common.MultiBytesToBigInts(marshalled)
}

func (cmt *HashCommitDecommit) Verify() bool {
	// Guard nil receiver explicitly: calling Verify on a typed-nil pointer
	// previously panicked at `cmt.C` dereference.
	if cmt == nil {
		return false
	}
	C, D := cmt.C, cmt.D
	if C == nil || D == nil {
		return false
	}
	// A decommitment carries the randomness in D[0] and at least one committed
	// secret after it, so fewer than two parts can never be a well-formed one.
	// Two concrete failures live below this line without the bound:
	//   len(D) == 0 -- common.SHA512_256i returns nil for an empty argument list,
	//     and the nil *big.Int is then dereferenced by hash.Cmp(C) below.
	//   len(D) == 1 -- Verify passes for anyone who supplies a matching C, and
	//     DeCommit's `cmt.D[1:]` hands the caller an empty decommitment.
	// Every call site in this repository already requires at least three parts,
	// so this bound rejects nothing that was previously accepted.
	if len(D) < 2 {
		return false
	}
	// common.SHA512_256i panics on nil *big.Int entries (unlike the
	// _TAGGED variant). Reject malformed decommitments up-front.
	for _, di := range D {
		if di == nil {
			return false
		}
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
