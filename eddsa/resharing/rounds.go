// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

const (
	TaskName = "eddsa-resharing"
)

type (
	base struct {
		*tss.ReSharingParameters
		temp        *localTempData
		input, save *keygen.LocalPartySaveData
		out         chan<- tss.Message
		end         chan<- *keygen.LocalPartySaveData
		oldOK,      // old committee "ok" tracker
		newOK []bool // `ok` tracks parties which have been verified by Update(); this one is for the new committee
		started bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	round4 struct {
		*round3
	}
	round5 struct {
		*round4
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*round4)(nil)
	_ tss.Round = (*round5)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.ReSharingParameters.Parameters
}

func (round *base) ReSharingParams() *tss.ReSharingParameters {
	return round.ReSharingParameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range append(round.oldOK, round.newOK...) {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	oldPs := round.OldParties().IDs()
	newPs := round.NewParties().IDs()
	idsMap := make(map[*tss.PartyID]bool)
	ids := make([]*tss.PartyID, 0, len(round.oldOK))
	for j, ok := range round.oldOK {
		if ok {
			continue
		}
		idsMap[oldPs[j]] = true
	}
	for j, ok := range round.newOK {
		if ok {
			continue
		}
		idsMap[newPs[j]] = true
	}
	// consolidate into the list
	for id := range idsMap {
		ids = append(ids, id)
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `oldOK` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.oldOK {
		round.oldOK[j] = false
	}
	for j := range round.newOK {
		round.newOK[j] = false
	}
}

// sets all pairings in `oldOK` to true
func (round *base) allOldOK() {
	for j := range round.oldOK {
		round.oldOK[j] = true
	}
}

// sets all pairings in `newOK` to true
func (round *base) allNewOK() {
	for j := range round.newOK {
		round.newOK[j] = true
	}
}

// getSSID derives this execution's session id from local params. Only the OLD
// committee can call it: the pre-image is the old committee's save data (its
// BigXj and its roster), which a new-committee party does not hold. That is
// precisely why DGRound1Message also carries a session_nonce_hash -- see
// sessionNonceHash below and round_2_new_step_1.go's oldSSIDUnanimous.
//
// The shape mirrors eddsa/keygen's getSSID (same curve fields, no B: the
// Edwards parameters expose no B) plus the old committee's BigXj, so two
// re-shares of two different keys never derive the same ssid.
func (round *base) getSSID() ([]byte, error) {
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)                                                         // parties
	BigXjList, err := crypto.FlattenECPoints(round.input.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...)                    // BigXj
	ssidList = append(ssidList, big.NewInt(int64(round.number))) // round number
	ssidList = append(ssidList, round.temp.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}

// sessionNonceHash is what the old committee declares and the new committee
// checks. It is a hash rather than the nonce itself so that the value on the
// wire does not hand a passive observer the identifier of a session it is not
// in; every party that IS in the session already holds the nonce and can
// recompute this.
//
// SCOPE. This makes a transcript non-portable between sessions for a peer that
// cannot forge messages. It does NOT authenticate the sender: nothing in this
// library signs or MACs a message, so an adversary who can rewrite arbitrary
// bytes on the wire can substitute the expected hash and splice the rest of a
// captured transcript. Transport authentication remains the host's job, exactly
// as it is for the rest of the protocol.
func sessionNonceHash(nonce *big.Int) []byte {
	if nonce == nil {
		return nil
	}
	return common.SHA512_256i(nonce).Bytes()
}
