package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *round8) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 8
	round.started = true
	round.resetOK()

	r8msg := NewSignRound8DecommitMessage(round.PartyID(), round.temp.DTelda)
	round.temp.signRound8DecommitMessage[round.PartyID().Index] = &r8msg
	round.out <- r8msg

	return nil
}

func (round *round8) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound8DecommitMessage {
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

func (round *round8) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*SignRound8DecommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round8) NextRound() tss.Round {
	round.started = false
	return &round9{round}
}
