package regroup

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()  // resets both round.oldOK and round.newOK
	round.allOldOK() // set `round.oldOK[0..n]` to true

	if round.ReGroupParams().IsOldCommittee() {
		round.allNewOK()
		return nil
	}

	// 2. "broadcast" "ACK" members of the OLD committee
	r2msg := NewDGRound2NewCommitteeACKMessage(round.OldParties().IDs(), round.PartyID())
	round.out <- r2msg

	return nil
}

func (round *round2) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*DGRound2NewCommitteeACKMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round2) Update() (bool, *tss.Error) {
	// accept messages from new -> old committee
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

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
