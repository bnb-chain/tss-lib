package keygen

import (
	"errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOk()

	Ps := round.Parties().IDs()
	PIDs := Ps.Keys()
	ecdsaPub := round.save.ECDSAPub

	// r3 messages are assumed to be available and != nil in this function
	r3msgs := round.temp.kgRound3PaillierProveMessage

	// 1-3. (concurrent)
	chs := make([]chan bool, len(r3msgs))
	for i := range chs {
		chs[i] = make(chan bool)
	}
	for j, msg := range r3msgs {
		if j == round.PartyID().Index { continue }
		go func(prf paillier.Proof2, j int, ch chan<- bool) {
			ppk := round.save.PaillierPks[j]
			ok, err := prf.Verify2(ppk.N, PIDs[j], ecdsaPub)
			if err != nil {
				common.Logger.Error(round.WrapError(err, Ps[j]).Error())
				ch <- false
				return
			}
			ch <- ok
		}(msg.Proof, j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)
	for j, ch := range chs {
		if j == round.PartyID().Index {
			round.ok[j] = true
			continue
		}
		round.ok[j] = <- ch
	}
	culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
	for j, ok := range round.ok {
		if !ok {
			culprits = append(culprits, Ps[j])
			common.Logger.Warningf("paillier verify failed for party %s", Ps[j])
			continue
		}
		common.Logger.Debugf("paillier verify passed for party %s", Ps[j])

	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("paillier verify failed"), culprits...)
	}
	return nil
}

func (round *round4) CanAccept(msg tss.Message) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
