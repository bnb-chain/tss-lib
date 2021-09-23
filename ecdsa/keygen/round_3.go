// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 5. Round 3.1 / Fig 6. Round 3.1
	for j, Pj := range round.Parties().IDs() {
		listToHash, err := crypto.FlattenECPoints(round.temp.r2msgVss[j])
		if err != nil {
			return round.WrapError(err, Pj)
		}
		listToHash = append(listToHash, round.save.PaillierPKs[j].N, round.save.NTildej[j], round.save.H1j[j], round.save.H2j[j])
		VjHash := common.SHA512_256i(listToHash...)
		if VjHash != round.temp.r1msgVHashs[j] {
			return round.WrapError(errors.New("verify hash failed"), Pj)
		}
	}

	// Fig 5. Round 3.2 TODO / Fig 6. Round 3.2 TODO_proofs 
	for j, Pj := range round.Parties().IDs() {
		Cij, err := round.save.PaillierPKs[j].Encrypt(round.temp.shares[j].Share)
		if err != nil {
			return round.WrapError(errors.New("encrypt error"))
		}
		r3msg1 := NewKGRound3Message(Pj, round.PartyID(), Cij)
		// do not send to this Pj, but store for round 3
		if j == i {
			round.temp.kgRound3Messages[i] = r3msg1
			continue
		}
		round.temp.kgRound3Messages[j] = r3msg1
		round.out <- r3msg1
	}

	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound3Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	// guard - VERIFY de-commit for all Pj
	for j, msg := range round.temp.kgRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
