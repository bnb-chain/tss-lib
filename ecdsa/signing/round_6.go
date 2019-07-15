package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round6) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.resetOK()

	piAi := schnorr.NewZKProof(round.temp.roi, round.temp.bigAi)
	piV := schnorr.NewZKVProof(round.temp.bigVi, round.temp.bigR, round.temp.si, round.temp.li)

	r6msg := NewSignRound6DecommitMessage(round.PartyID(), round.temp.DPower, piAi, piV)
	round.temp.signRound6DecommitMessage[round.PartyID().Index] = &r6msg
	round.out <- r6msg
	return nil
}

func (round *round6) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound6DecommitMessage {
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

func (round *round6) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*SignRound6DecommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round6) NextRound() tss.Round {
	round.started = false
	return &round7{round}
}
