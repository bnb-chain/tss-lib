// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package commitments_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
)

// DeCommit hashes every part it is handed before anything looks at how many
// there are. The four call sites whose expected length is a function of the
// threshold -- {ecdsa,eddsa}/{keygen,resharing} -- could not state that length
// at the message layer, so they checked it on DeCommit's OUTPUT. This pins the
// cost that ordering carried, so the reason those call sites now check first
// does not have to be taken on trust.
//
// It asserts nothing about the library's own behaviour; it measures the
// primitive, which is why it lives here rather than in one of the four.
func TestDeCommitCostGrowsWithThePartCountItIsGiven(t *testing.T) {
	build := func(parts int) *HashCommitDecommit {
		D := make(HashDeCommitment, parts)
		for i := range D {
			D[i] = big.NewInt(int64(i + 1))
		}
		// A commitment that does not match, so Verify fails either way and the
		// only thing being measured is what it costs to find that out.
		return &HashCommitDecommit{C: big.NewInt(1), D: D}
	}
	measure := func(parts int) time.Duration {
		cmt := build(parts)
		best := time.Duration(1<<62 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			ok, _ := cmt.DeCommit()
			assert.False(t, ok, "a mismatched commitment must not open")
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}

	small := measure(7) // a threshold-2 committee: (2+1)*2 + 1
	large := measure(200000)

	t.Logf("DeCommit on a mismatched commitment: 7 parts=%s, 200000 parts=%s", small, large)
	assert.Greater(t, large, 20*small,
		"DeCommit is expected to scale with the part count (7=%s, 200000=%s); if it no "+
			"longer does, the four call sites that check the count before calling it "+
			"are still correct, but this test no longer says why", small, large)
}

// The part count is all that changes: DeCommit still opens a commitment whose
// decommitment matches, and still refuses one whose does not.
func TestDeCommitStillOpensAndRefuses(t *testing.T) {
	secrets := []*big.Int{big.NewInt(11), big.NewInt(22)}
	cmt := NewHashCommitmentWithRandomness(big.NewInt(99), secrets...)

	ok, values := cmt.DeCommit()
	assert.True(t, ok, "a matching decommitment must open")
	assert.Len(t, values, len(secrets), "the randomness is not part of the payload")

	tampered := &HashCommitDecommit{C: cmt.C, D: append(HashDeCommitment{big.NewInt(98)}, secrets...)}
	ok, _ = tampered.DeCommit()
	assert.False(t, ok, "a mismatched decommitment must not open")
}

// A decommitment carries the randomness in D[0] and at least one committed
// secret after it, so fewer than two parts is never well-formed. Verify refuses
// both short shapes, and DeCommit therefore never reaches its D[1:].
//
// Both were reachable before the bound, and they failed differently:
//
//	len(D) == 0 -- common.SHA512_256i returns nil for an empty argument list,
//	  and Verify then dereferenced that nil in hash.Cmp(C). A caller needed no
//	  knowledge of C to crash the process; any C would do. Hence NotPanics.
//	len(D) == 1 -- Verify passed for anyone who supplied a matching C, and
//	  DeCommit handed back an empty decommitment that a caller checking only
//	  `flatPolyGs == nil` would accept.
//
// Every call site in this repository already requires at least three parts, so
// the bound rejects nothing that was previously accepted -- that half is what
// TestDeCommitStillOpensAndRefuses and the round-3 tests pin.
func TestVerifyRefusesFewerThanTwoParts(t *testing.T) {
	t.Run("zero parts, no panic", func(tt *testing.T) {
		cmt := &HashCommitDecommit{C: big.NewInt(42), D: HashDeCommitment{}}
		assert.NotPanics(tt, func() {
			assert.False(tt, cmt.Verify(), "an empty decommitment must not verify")
		}, "an empty decommitment must not panic the caller")

		ok, values := cmt.DeCommit()
		assert.False(tt, ok)
		assert.Nil(tt, values)
	})

	t.Run("one part, even with a matching commitment", func(tt *testing.T) {
		r := big.NewInt(12345)
		// The commitment the primitive itself would produce for [r] alone.
		matching := NewHashCommitmentWithRandomness(r)
		assert.Len(tt, matching.D, 1, "the builder produces exactly [r] here")

		assert.False(tt, matching.Verify(),
			"a decommitment carrying no secret must not verify even against its own C")

		ok, values := matching.DeCommit()
		assert.False(tt, ok)
		assert.Nil(tt, values, "and it must not hand back an empty payload as if it opened")
	})

	t.Run("two parts still open", func(tt *testing.T) {
		cmt := NewHashCommitmentWithRandomness(big.NewInt(99), big.NewInt(7))
		ok, values := cmt.DeCommit()
		assert.True(tt, ok, "the bound must not reject the smallest well-formed shape")
		assert.Len(tt, values, 1)
		assert.Equal(tt, 0, values[0].Cmp(big.NewInt(7)))
	})
}
