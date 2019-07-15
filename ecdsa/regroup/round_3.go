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
	round.resetOK()  // resets both round.oldOK and round.newOK
	round.allOldOK() // set `round.oldOK[0..n]` to true

	if round.ReGroupParams().IsNewCommittee() {
		round.allNewOK()
		return nil
	}

	// 2. send share to Pj from the new committee
	for j, Pj := range round.NewParties().IDs() {
		share := round.temp.NewShares[j]
		r3msg1 := NewDGRound3ShareMessage(Pj, round.PartyID(), share)
		round.out <- r3msg1
	}

	deCommitment := round.temp.Di
	r3msg2 := NewDGRound3DeCommitMessage(round.NewParties().IDs(), round.PartyID(), deCommitment)
	round.out <- r3msg2

	return nil
}

func (round *round3) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*DGRound3ShareMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round3) Update() (bool, *tss.Error) {
 	for j, msg := range round.temp.dgRound2NewCommitteeACKMessage {
		if round.newOK[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		round.newOK[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
