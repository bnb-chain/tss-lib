// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/tss"
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.ReSharingParameters, save *keygen.LocalPartySaveData, temp *LocalTempData, out chan<- tss.Message) tss.Round {
	return &round1{
		&base{params, save, temp, out, make([]bool, params.Threshold()+1), make([]bool, len(params.NewParties().IDs())), false, 1}}
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

	Pi := round.PartyID()
	i := Pi.Index

	// 1. PrepareForSigning() -> w_i
	xi := round.save.Xi
	ks := round.save.Ks
	bigXs := round.save.BigXj
	newKs := round.NewParties().IDs().Keys()
	wi, _ := signing.PrepareForSigning(i, round.Threshold()+1, xi, ks, round.save.BigXj)

	// 2.
	vi, shares, err := vss.Create(round.NewThreshold(), wi, newKs)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 3.
	flatVis, err := crypto.FlattenECPoints(vi)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// include "Big X's" and list of indexes (k_j) known by this party in the commitment
	flatBigXs, err := crypto.FlattenECPoints(bigXs)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	cBuilder := commitments.NewBuilder()
	secrets, err := cBuilder.AddPart(flatBigXs).AddPart(round.save.Ks).Secrets()
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	cmtR := round.save.ECDSAPub.X()
	xAndKCmt := commitments.NewHashCommitmentWithRandomness(cmtR, secrets...)

	vCmt := commitments.NewHashCommitment(flatVis...)

	// 4. populate temp data
	round.temp.VD = vCmt.D
	round.temp.XAndKD = xAndKCmt.D
	round.temp.NewShares = shares

	// 5. "broadcast" C_i to members of the NEW committee
	r1msg := NewDGRound1Message(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		round.save.ECDSAPub, vCmt.C, xAndKCmt.C)
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
	for j, msg := range round.temp.dgRound1Messages {
		if round.oldOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.oldOK[j] = true

		// save the ecdsa pub received from the old committee
		r1msg := round.temp.dgRound1Messages[0].Content().(*DGRound1Message)
		candidate, err := r1msg.UnmarshalECDSAPub()
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
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
