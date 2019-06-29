package signing

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 10
	round.started = true
	round.resetOk()

	sumS := round.temp.si
	for j := range round.Parties().Parties() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		sumS = new(big.Int).Add(sumS, round.temp.signRound9SignatureMessage[j].Si)
	}

	round.data.Signature = append(round.temp.r.Bytes(), sumS.Bytes()...)

	return nil
}

func (round *finalization) CanAccept(msg tss.Message) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
