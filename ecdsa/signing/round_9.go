package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
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
		if !ok && len(values) != 4 {
			return round.WrapError(errors.New("de-commitment for bigVj and bigAj failed"), Pj)
		}
		UjX, UjY, TjX, TjY := values[0], values[1], values[2], values[3]
		UX, UY = tss.EC().Add(UX, UY, UjX, UjY)
		TX, TY = tss.EC().Add(TX, TY, TjX, TjY)
	}
	if UX.Cmp(TX) != 0 || UY.Cmp(TY) != 0 {
		return round.WrapError(errors.New("U doesn't equal T"), round.PartyID())
	}

	r9msg := NewSignRound9Message(round.PartyID(), round.temp.si)
	round.temp.signRound9Messages[round.PartyID().Index] = r9msg
	round.out <- r9msg
	return nil
}

func (round *round9) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound9Messages {
		if msg == nil || round.ok[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
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
