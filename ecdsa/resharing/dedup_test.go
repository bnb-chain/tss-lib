// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	. "github.com/bnb-chain/tss-lib/v4/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// TestStoreMessageRejectsCrossCommitteeReplacement is a regression test for the
// resharing-specific gap in the intra-session message-replacement guard.
//
// Resharing has two independent, overlapping committee index spaces. The guard
// originally exempted "self" via `fromPIdx == p.PartyID().Index`, comparing a
// single index against both spaces. A new-committee party whose new index
// happened to equal an old-committee peer's old index would therefore
// mis-classify that peer as "self" (isDup=false) and silently accept a
// replacement of the peer's already-stored commitment — exactly the
// intra-session replacement the guard is meant to block. The fix detects
// self-echoes by sender IDENTITY (key) rather than by index.
func TestStoreMessageRejectsCrossCommitteeReplacement(t *testing.T) {
	a := assert.New(t)
	ec := tss.S256()

	// Two disjoint committees, both index-0-based, so a new-committee party and
	// an old-committee party can share the numeric index 0 with distinct keys.
	oldPIDs := tss.GenerateTestPartyIDs(testThreshold + 1)
	newPIDs := tss.GenerateTestPartyIDs(testThreshold + 1)
	oldCtx := tss.NewPeerContext(oldPIDs)
	newCtx := tss.NewPeerContext(newPIDs)

	// `p` is a NEW-committee-only party at new-index 0.
	self := newPIDs[0]
	params := tss.NewReSharingParameters(ec, oldCtx, newCtx, self,
		len(oldPIDs), testThreshold, len(newPIDs), testThreshold)
	p := NewLocalParty(params, keygen.NewLocalPartySaveData(len(newPIDs)), nil, nil)

	// The colliding peer is the OLD-committee party at old-index 0.
	oldPeer := oldPIDs[0]
	a.True(params.IsNewCommittee())
	a.False(params.IsOldCommittee())
	a.Equal(p.PartyID().Index, oldPeer.Index, "precondition: indices collide across committees")
	a.NotEqual(0, p.PartyID().KeyInt().Cmp(oldPeer.KeyInt()), "precondition: identities differ")

	pub := crypto.ScalarBaseMult(ec, big.NewInt(7))
	ssid := []byte("test-ssid")
	mkMsg := func(commitment *big.Int) tss.ParsedMessage {
		// DGRound1Message is an old-committee-sourced broadcast; `from` is the
		// old peer whose old-index collides with this party's new-index.
		return NewDGRound1Message(newPIDs, oldPeer, pub, commitment, ssid, []byte("nonce-hash"))
	}

	// 1. First DGRound1Message from the old peer is accepted.
	ok, err := p.StoreMessage(mkMsg(big.NewInt(0xC0FFEE)))
	a.True(ok)
	a.Nil(err)

	// 2. A DIFFERENT-content DGRound1Message from the SAME old peer is rejected.
	//    Before the fix this was silently accepted (overwriting the stored
	//    commitment) because the old peer's index collided with selfIdx.
	ok, err = p.StoreMessage(mkMsg(big.NewInt(0xBADBEEF)))
	a.False(ok)
	a.NotNil(err)

	// 3. An identical re-send is still tolerated (idempotent at-least-once
	//    delivery must not be mistaken for adversarial replacement).
	dup := mkMsg(big.NewInt(0xC0FFEE))
	ok, err = p.StoreMessage(dup)
	a.True(ok)
	a.Nil(err)
	ok, err = p.StoreMessage(dup)
	a.True(ok)
	a.Nil(err)
}
