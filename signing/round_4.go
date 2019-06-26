package signing

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/tss"
)

// missing:
// line5: SchnorrProve of Gamma
func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 4
	round.started = true
	round.resetOk()

	thelta := *round.temp.thelta
	theltaInverse := &thelta
	for j, _ := range round.Parties().Parties() {
		if j == round.PartyID().Index {
			continue
		}
		theltaJ := round.temp.signRound3Messages[j].Thelta
		theltaInverse = new(big.Int).Mod(new(big.Int).Add(theltaInverse, theltaJ), tss.EC().Params().N)
	}

	// compute the multiplicative inverse thelta mod q
	theltaInverse = new(big.Int).ModInverse(theltaInverse, tss.EC().Params().N)
	//schnorr.NewZKProof(round.temp.gamma, )
	round.temp.thelta_inverse = theltaInverse
	r4msg := NewSignRound4DecommitMessage(round.PartyID(), round.temp.deCommit, nil)
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
