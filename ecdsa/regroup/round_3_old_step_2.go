package regroup

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allNewOK()

	if !round.ReGroupParams().IsOldCommittee() {
		return nil
	}

	// 2. send share to Pj from the new committee
	for j, Pj := range round.NewParties().IDs() {
		share := round.temp.NewShares[j]
		r3msg1 := NewDGRound3ShareMessage(Pj, round.PartyID(), share)
		round.out <- r3msg1
	}

	deCommitment := round.temp.Di
	r3msg2 := NewDGRound3DeCommitMessage(round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(), deCommitment)
	round.out <- r3msg2

	return nil
}

func (round *round3) CanAccept(msg tss.Message) bool {
	if msg1, ok := msg.(*DGRound3ShareMessage); !ok || msg1 == nil {
		if msg2, ok := msg.(*DGRound3DeCommitMessage); !ok || msg2 == nil {
			return false
		}
	}
	return true
}

func (round *round3) Update() (bool, *tss.Error) {
	// only the new committee receive in this round
	if !round.ReGroupParams().IsNewCommittee() {
		return true, nil
	}
	// accept messages from old -> new committee
	for j, msg := range round.temp.dgRound3ShareMessage {
		if round.oldOK[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.dgRound3DeCommitMessage[j]
		if !round.CanAccept(msg2) {
			return false, nil
		}
		round.oldOK[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
