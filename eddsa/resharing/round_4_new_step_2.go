// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"math/big"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK

	round.allOldOK()

	if !round.ReSharingParams().IsNewCommittee() {
		// both committees proceed to round 5 after receiving "ACK" messages from the new committee
		return nil
	}

	Pi := round.PartyID()
	i := Pi.Index

	// 1.
	newXi := big.NewInt(0)

	// 2-8.
	modQ := common.ModInt(tss.EC().Params().N)
	vjc := make([][]*crypto.ECPoint, round.Threshold()+1)
	for j := 0; j <= round.Threshold(); j++ { // P1..P_t+1. Ps are indexed from 0 here
		r1msg := round.temp.dgRound1Messages[j].Content().(*DGRound1Message)
		r3msg2 := round.temp.dgRound3Message2s[j].Content().(*DGRound3Message2)

		vCj, vDj := r1msg.UnmarshalVCommitment(), r3msg2.UnmarshalVDeCommitment()

		// 3. unpack flat "v" commitment content
		vCmtDeCmt := commitments.HashCommitDecommit{C: vCj, D: vDj}
		ok, flatVs := vCmtDeCmt.DeCommit()
		if !ok || len(flatVs) != (round.NewThreshold()+1)*2 { // they're points so * 2
			// TODO collect culprits and return a list of them as per convention
			return round.WrapError(errors.New("de-commitment of v_j0..v_jt failed"), round.Parties().IDs()[j])
		}
		vj, err := crypto.UnFlattenECPoints(tss.EC(), flatVs)
		if err != nil {
			return round.WrapError(err, round.Parties().IDs()[j])
		}
		vjc[j] = vj

		r3msg1 := round.temp.dgRound3Message1s[j].Content().(*DGRound3Message1)
		sharej := &vss.Share{
			Threshold: round.NewThreshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     new(big.Int).SetBytes(r3msg1.Share),
		}
		if ok := sharej.Verify(round.NewThreshold(), vj); !ok {
			return round.WrapError(errors.New("share from old committee did not pass Verify()"), round.Parties().IDs()[j])
		}

		newXi = new(big.Int).Add(newXi, sharej.Share)
	}

	// 9-12.
	var err error
	Vc := make([]*crypto.ECPoint, round.NewThreshold()+1)
	for c := 0; c <= round.NewThreshold(); c++ {
		Vc[c] = vjc[0][c]
		for j := 1; j <= round.Threshold(); j++ {
			Vc[c], err = Vc[c].Add(vjc[j][c])
			if err != nil {
				return round.WrapError(errors.Wrapf(err, "Vc[c].Add(vjc[j][c])"))
			}
		}
	}

	// 13-15.
	if !Vc[0].Equals(round.save.EDDSAPub) {
		return round.WrapError(errors.New("assertion failed: V_0 != y"), round.PartyID())
	}

	// 16-20.
	newKs := make([]*big.Int, 0, round.NewPartyCount())
	newBigXjs := make([]*crypto.ECPoint, round.NewPartyCount())
	culprits := make([]*tss.PartyID, 0, round.NewPartyCount()) // who caused the error(s)
	for j := 0; j < round.NewPartyCount(); j++ {
		Pj := round.NewParties().IDs()[j]
		kj := Pj.KeyInt()
		newBigXj := Vc[0]
		newKs = append(newKs, kj)
		z := new(big.Int).SetInt64(int64(1))
		for c := 1; c <= round.NewThreshold(); c++ {
			z = modQ.Mul(z, kj)
			newBigXj, err = newBigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				culprits = append(culprits, Pj)
			}
		}
		newBigXjs[j] = newBigXj
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.Wrapf(err, "newBigXj.Add(Vc[c].ScalarMult(z))"), culprits...)
	}

	round.temp.newXi = newXi
	round.temp.newKs = newKs
	round.temp.newBigXjs = newBigXjs

	// 21. Send an "ACK" message to both committees to signal that we're ready to save our data
	r4msg := NewDGRound4Message(round.OldAndNewParties(), Pi)
	round.temp.dgRound4Messages[i] = r4msg
	round.out <- r4msg

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DGRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// accept messages from new -> old&new committees
	for j, msg := range round.temp.dgRound4Messages {
		if round.newOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.newOK[j] = true
	}
	return true, nil
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
