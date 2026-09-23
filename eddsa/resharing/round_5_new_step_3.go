// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"

	"github.com/bnb-chain/tss-lib/v4/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true

	round.allOldOK()
	round.allNewOK()

	if round.IsNewCommittee() {
		// for this P: SAVE data
		round.save.BigXj = round.temp.newBigXjs
		round.save.ShareID = round.PartyID().KeyInt()
		round.save.Xi = round.temp.newXi
		round.save.Ks = round.temp.newKs

	} else if round.IsOldCommittee() {
		// Set this round's own copy of the old share to zero.
		//
		// Two things this is NOT. It is not the caller's copy: since
		// keygen.BuildLocalSaveDataSubset deep-copies LocalSecrets, this cannot
		// reach the save data the caller passed in, and must not.
		// And it is not an erasure. big.Int.SetInt64 truncates the abs slice to
		// length zero; the backing array keeps every word, so the value reads as
		// 0 while the secret is still in that allocation. Nothing in Go erases a
		// big.Int -- see doc/maintenance-invariants.md section 7.
		round.input.Xi.SetInt64(0)
	}

	round.end <- round.save
	return nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	return false
}

func (round *round5) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *round5) NextRound() tss.Round {
	return nil // both committees are finished!
}
