// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	errors2 "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

func (round *round9) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 9
	round.started = true
	round.resetOK()

	UX, UY := round.temp.Ui.X(), round.temp.Ui.Y()
	TX, TY := round.temp.Ti.X(), round.temp.Ti.Y()
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}

		r7msg := round.temp.signRound7Messages[j].Content().(*SignRound7Message)
		r8msg := round.temp.signRound8Messages[j].Content().(*SignRound8Message)
		cj, dj := r7msg.UnmarshalCommitment(), r8msg.UnmarshalDeCommitment()
		cmt := commitments.HashCommitDecommit{C: cj, D: dj}
		ok, values := cmt.DeCommit()
		if !ok || len(values) != 4 {
			return round.WrapError(errors.New("de-commitment for bigVj and bigAj failed"), Pj)
		}
		UjX, UjY, TjX, TjY := values[0], values[1], values[2], values[3]
		Uj, err := crypto.NewECPoint(round.Params().EC(), UjX, UjY)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(Uj)"), Pj)
		}
		Tj, err := crypto.NewECPoint(round.Params().EC(), TjX, TjY)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(Tj)"), Pj)
		}
		UX, UY = round.Params().EC().Add(UX, UY, Uj.X(), Uj.Y())
		TX, TY = round.Params().EC().Add(TX, TY, Tj.X(), Tj.Y())
	}
	if UX.Cmp(TX) != 0 || UY.Cmp(TY) != 0 {
		// This check sums a contribution from every party, so it cannot pinpoint
		// which peer supplied an inconsistent (U_j, T_j) -- but the culprit is
		// never the reporting party, which merely detected the mismatch.
		// Attributing it to round.PartyID() charged the detector and left a
		// misbehaving peer unnamed across repeated attempts.
		culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs())-1)
		for j, Pj := range round.Parties().IDs() {
			if j == round.PartyID().Index {
				continue
			}
			culprits = append(culprits, Pj)
		}
		return round.WrapError(errors.New("U doesn't equal T"), culprits...)
	}

	r9msg := NewSignRound9Message(round.PartyID(), round.temp.si)
	round.temp.signRound9Messages[round.PartyID().Index] = r9msg
	round.out <- r9msg
	return nil
}

func (round *round9) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound9Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round9) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound9Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round9) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
