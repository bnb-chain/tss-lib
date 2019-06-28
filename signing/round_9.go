package signing

import (
	"errors"
	"fmt"

	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round9) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 9
	round.started = true
	round.resetOk()

	UX, UY := round.temp.Ui.X(), round.temp.Ui.Y()
	TX, TY := round.temp.Ti.X(), round.temp.Ti.Y()
	fmt.Printf("[cong] idx: %d, verify Ui: (%s, %s), Ti: (%s, %s)\n", round.PartyID().Index, UX, UY, TX, TY)
	for j, Pj := range round.Parties().Parties() {
		if j == round.PartyID().Index {
			continue
		}

		cj := round.temp.signRound7CommitMessage[j].Commitment
		dj := round.temp.signRound8DecommitMessage[j].Decommitment
		cmt := commitments.HashCommitDecommit{cj, dj}
		ok, values := cmt.DeCommit()
		if !ok && len(values) != 4 {
			return round.WrapError(errors.New("decommitment for bigVj and bigAj failed"), Pj)
		}
		UjX, UjY, TjX, TjY := values[0], values[1], values[2], values[3]
		fmt.Printf("[CONG] idx: %d, received idx: %d, U: (%s, %s), T: (%s, %s)\n", round.PartyID().Index, j, UjX.String(), UjY.String(), TjX.String(), TjY.String())
		UX, UY = tss.EC().Add(UX, UY, UjX, UjY)
		TX, TY = tss.EC().Add(TX, TY, TjX, TjY)
	}
	fmt.Printf("idx: %d\nux: %s\ntx: %s\nuy: %s\nty: %s\n", round.PartyID().Index, UX, TX, UY, TY)
	if UX.Cmp(TX) != 0 || UY.Cmp(TY) != 0 {
		return round.WrapError(errors.New("U doesn't equals to T"), round.PartyID())
	}

	r9msg := NewSignRound9SignatureMessage(round.PartyID(), round.temp.si)
	round.temp.signRound9SignatureMessage[round.PartyID().Index] = &r9msg
	round.out <- r9msg
	return nil
}

func (round *round9) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound9SignatureMessage {
		if round.ok[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round9) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*SignRound9SignatureMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round9) NextRound() tss.Round {
	return nil
}
