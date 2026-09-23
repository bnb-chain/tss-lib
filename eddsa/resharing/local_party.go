// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	cmt "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.ReSharingParameters

		temp        localTempData
		input, save keygen.LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *keygen.LocalPartySaveData
	}

	localMessageStore struct {
		dgRound1Messages,
		dgRound2Messages,
		dgRound3Message1s,
		dgRound3Message2s,
		dgRound4Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after rounds)
		NewVs     vss.Vs
		NewShares vss.Shares
		VD        cmt.HashDeCommitment

		// temporary storage of data that is persisted by the new party in round 5 if all "ACK" messages are received
		newXi     *big.Int
		newKs     []*big.Int
		newBigXjs []*crypto.ECPoint // Xj to save in round 5

		ssid      []byte
		ssidNonce *big.Int
	}
)

// Exported, used in `tss` client
// The `key` is READ FROM and never written to. An old-committee party works on
// a deep copy of `key.LocalSecrets`, so nothing this library does reaches the
// caller's own save data.
// This library does not erase your pre-re-share secret -- and could not time it
// if it did. See doc/maintenance-invariants.md section 7.
func NewLocalParty(
	params *tss.ReSharingParameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- *keygen.LocalPartySaveData,
) tss.Party {
	oldPartyCount := len(params.OldParties().IDs())
	subset := key
	if params.IsOldCommittee() {
		subset = keygen.BuildLocalSaveDataSubset(key, params.OldParties().IDs())
	}
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		input:     subset,
		save:      keygen.NewLocalPartySaveData(params.NewPartyCount()),
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.dgRound1Messages = make([]tss.ParsedMessage, oldPartyCount)          // from t+1 of Old Committee
	p.temp.dgRound2Messages = make([]tss.ParsedMessage, params.NewPartyCount()) // from n of New Committee
	p.temp.dgRound3Message1s = make([]tss.ParsedMessage, oldPartyCount)         // from t+1 of Old Committee
	p.temp.dgRound3Message2s = make([]tss.ParsedMessage, oldPartyCount)         // "
	p.temp.dgRound4Messages = make([]tss.ParsedMessage, params.NewPartyCount()) // from n of New Committee

	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.input, &p.save, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// Resolve which committee this message type is sourced from, then check the
	// sender against THAT committee twice: the array bound, and identity-to-slot.
	//
	// The bound alone is not an admission check. The old and new committees have
	// INDEPENDENT index spaces, so "old slot j" and "new slot j" are different
	// parties; an index that merely fits the array says nothing about whether the
	// sender belongs to the committee the message type implies. Without the second
	// test an old-committee-only party can, using its own PartyID, occupy the
	// new-committee slot at its own old index (SRC-2026-1721).
	//
	// The second test compares against roster[Index] rather than scanning the
	// whole roster, because StoreMessage below files the message by that same
	// Index. Mere membership ("the sender is somewhere on this roster") would
	// still let a message be filed into a slot belonging to a different member.
	// Comparison is by KEY: PartyID.Index is assigned per sorted roster and is not
	// carried on the wire, so it is the receiver's own view, while Key is the
	// sender's identity. StoreMessage's self-echo dedup uses KeyInt() for the same
	// reason.
	//
	// Ordering is load-bearing. BaseParty.ValidateMessage above has already
	// established From != nil and Index >= 0; the bound check below establishes
	// Index <= len(roster)-1. Only then is roster[Index] safe to evaluate. An
	// empty roster yields maxFromIdx == -1 and is rejected by the bound check.
	//
	// This mirrors the ecdsa/resharing fix verbatim; the only difference is that
	// this package carries DGRound2Message / DGRound4Message where ecdsa splits
	// each into a ...1 / ...2 pair.
	var roster tss.SortedPartyIDs
	switch msg.Content().(type) {
	case *DGRound2Message, *DGRound4Message:
		roster = p.params.NewParties().IDs()
	default:
		roster = p.params.OldParties().IDs()
	}
	maxFromIdx := len(roster) - 1
	if maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	if roster[msg.GetFrom().Index].KeyInt().Cmp(msg.GetFrom().KeyInt()) != 0 {
		return false, p.WrapError(fmt.Errorf(
			"received %T from a party that is not on the committee that message type comes from",
			msg.Content()), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round.
	// Each branch rejects intra-session message replacement: once a slot is
	// filled, a different-content message for it is rejected (idempotent
	// identical re-sends are tolerated via tss.IsSameMessage).
	//
	// Resharing spans two independent, overlapping committee index spaces:
	// old-committee-sourced slots (dgRound1Messages, dgRound3Message1s,
	// dgRound3Message2s) are indexed by the sender's OLD index, new-sourced
	// slots (dgRound2Messages, dgRound4Messages) by the sender's NEW index. A
	// peer's index in one committee can numerically equal this party's index in
	// the other, so p.PartyID().Index is NOT a safe self-echo discriminator: it
	// would mis-read a colliding cross-committee peer as "self" and skip the
	// duplicate guard. Detect our own echoes by sender IDENTITY (key) instead.
	isDup := msg.GetFrom().KeyInt().Cmp(p.PartyID().KeyInt()) != 0

	dupErr := func() (bool, *tss.Error) {
		return false, p.WrapError(
			fmt.Errorf("duplicate %T from party %d", msg.Content(), fromPIdx),
			msg.GetFrom())
	}
	switch msg.Content().(type) {
	case *DGRound1Message:
		if isDup && p.temp.dgRound1Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound1Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound1Messages[fromPIdx] = msg
	case *DGRound2Message:
		if isDup && p.temp.dgRound2Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound2Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound2Messages[fromPIdx] = msg
	case *DGRound3Message1:
		if isDup && p.temp.dgRound3Message1s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound3Message1s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound3Message1s[fromPIdx] = msg
	case *DGRound3Message2:
		if isDup && p.temp.dgRound3Message2s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound3Message2s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound3Message2s[fromPIdx] = msg
	case *DGRound4Message:
		if isDup && p.temp.dgRound4Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.dgRound4Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.dgRound4Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
