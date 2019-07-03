package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 4
	round.started = true
	round.resetOk()

	thelta := *round.temp.thelta
	theltaInverse := &thelta

	modN := common.ModInt(tss.EC().Params().N)

	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		theltaJ := round.temp.signRound3Messages[j].Thelta
		theltaInverse = modN.Add(theltaInverse, theltaJ)
	}

	// compute the multiplicative inverse thelta mod q
	theltaInverse = modN.ModInverse(theltaInverse)
	bigGammaX, bigGammaY := tss.EC().ScalarBaseMult(round.temp.gamma.Bytes())
	bigGamma := crypto.NewECPoint(tss.EC(), bigGammaX, bigGammaY)
	piGamma := schnorr.NewZKProof(round.temp.gamma, bigGamma)
	round.temp.thelta_inverse = theltaInverse
	r4msg := NewSignRound4DecommitMessage(round.PartyID(), round.temp.deCommit, piGamma)
	round.temp.signRound4DecommitMessage[round.PartyID().Index] = &r4msg
	round.out <- r4msg

	return nil
}

func (round *round4) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound4DecommitMessage {
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

func (round *round4) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*SignRound4DecommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
