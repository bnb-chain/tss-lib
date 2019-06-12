package keygen

import (
	"errors"
	"fmt"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/types"
)

func (round *round4) start() *keygenError {
	if round.started {
		return round.wrapError(errors.New("round already started"), nil)
	}
	round.number = 4
	round.started = true
	round.resetOk()

	Pj := round.p2pCtx.Parties()
	kj := Pj.Keys()
	ecdsaPub := round.save.ECDSAPub

	r3msgs := round.temp.kgRound3PaillierProveMessage
	for i, msg := range r3msgs {
		if msg == nil {
			return round.wrapError(fmt.Errorf("r3msg %d is nil", i), nil)
		}
	}

	// 1-3. (concurrent)
	chs := make([]chan bool, len(r3msgs))
	for i := range chs {
		chs[i] = make(chan bool)
	}
	for j, msg := range r3msgs {
		if j == round.partyID.Index {
			continue
		}
		go func(prf paillier.Proof2, j int, ch chan<- bool) {
			ppk := round.save.PaillierPks[j]
			ok, err := prf.Verify2(ppk.N, kj[j], ecdsaPub)
			if err != nil {
				common.Logger.Error(round.wrapError(err, Pj[j]).Error())
				ch <- false
				return
			}
			ch <- ok
		}(msg.Proof, j, chs[j])
	}
	for j, ch := range chs {
		if j == round.partyID.Index {
			round.ok[j] = true
			continue
		}
		round.ok[j] = <- ch
		if !round.ok[j] {
			return round.wrapError(errors.New("paillier verify failed"), Pj[j])
		}
		common.Logger.Debugf("paillier verify passed for party %s", Pj[j])
	}

	return nil
}

func (round *round4) canAccept(msg types.Message) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) update() (bool, *keygenError) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) nextRound() round {
	return nil // finished!
}
