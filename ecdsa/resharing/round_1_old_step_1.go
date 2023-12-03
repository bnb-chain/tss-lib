// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.ReSharingParameters, input, save *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *keygen.LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, temp, input, save, out, end, make([]bool, len(params.OldParties().IDs())), make([]bool, len(params.NewParties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allNewOK()

	if !round.ReSharingParams().IsOldCommittee() {
		return nil
	}
	round.allOldOK()

	round.temp.ssidNonce = new(big.Int).SetUint64(uint64(0))
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}
	round.temp.ssid = ssid
	Pi := round.PartyID()
	i := Pi.Index

	// 1. PrepareForSigning() -> w_i
	xi, ks, bigXj := round.input.Xi, round.input.Ks, round.input.BigXj
	if round.Threshold()+1 > len(ks) {
		return round.WrapError(fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks)), round.PartyID())
	}
	newKs := round.NewParties().IDs().Keys()
	wi, _ := signing.PrepareForSigning(round.Params().EC(), i, len(round.OldParties().IDs()), xi, ks, bigXj)

	// 2.
	vi, shares, err := vss.Create(round.Params().EC(), round.NewThreshold(), wi, newKs)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 3.
	flatVis, err := crypto.FlattenECPoints(vi)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	vCmt := commitments.NewHashCommitment(flatVis...)

	// 4. populate temp data
	round.temp.VD = vCmt.D
	round.temp.NewShares = shares

	// 5. "broadcast" C_i to members of the NEW committee
	r1msg := NewDGRound1Message(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		round.input.ECDSAPub, vCmt.C, ssid)
	round.temp.dgRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	// accept messages from old -> new committee
	if _, ok := msg.Content().(*DGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	// only the new committee receive in this round
	if !round.ReSharingParameters.IsNewCommittee() {
		return true, nil
	}
	// accept messages from old -> new committee
	ret := true
	for j, msg := range round.temp.dgRound1Messages {
		if round.oldOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.oldOK[j] = true

		// save the ecdsa pub received from the old committee
		if round.temp.dgRound1Messages[0] == nil {
			ret = false
			continue
		}
		r1msg := round.temp.dgRound1Messages[0].Content().(*DGRound1Message)
		candidate, err := r1msg.UnmarshalECDSAPub(round.Params().EC())
		if err != nil {
			return false, round.WrapError(errors.New("unable to unmarshal the ecdsa pub key"), msg.GetFrom())
		}
		if round.save.ECDSAPub != nil &&
			!candidate.Equals(round.save.ECDSAPub) {
			// uh oh - anomaly!
			return false, round.WrapError(errors.New("ecdsa pub key did not match what we received previously"), msg.GetFrom())
		}
		round.save.ECDSAPub = candidate
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
