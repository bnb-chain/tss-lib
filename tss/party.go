package tss

import (
	"github.com/binance-chain/tss-lib/common"
)

type Party interface {
	Start() *Error
	Update(msg Message) (ok bool, err *Error)
	PartyID() *PartyID
	WaitingFor() []*PartyID
	String() string
	validateMessage(msg Message) (bool, *Error)
	storeMessage(msg Message) (bool, *Error)
	finish()
	rnd() Round
	lock()
	unlock()
}

func BaseUpdate(p Party, msg Message) (ok bool, err *Error) {
	if _, err := p.validateMessage(msg); err != nil {
		return false, err
	}
	// need this mtx unlock hook, L137 is recursive so cannot use defer
	r := func(ok bool, err *Error) (bool, *Error) {
		p.unlock()
		return ok, err
	}
	p.lock() // data is written to P state below
	common.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
	if p.rnd() != nil {
		common.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.rnd().RoundNumber(), msg.String())
	}
	if ok, err := p.storeMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.rnd() != nil {
		common.Logger.Debugf("party %s: keygen round %d update", p.rnd().Params().PartyID(), p.rnd().RoundNumber())
		if _, err := p.rnd().Update(); err != nil {
			return r(false, err)
		}
		if p.rnd().CanProceed() {
			if p.rnd() = p.rnd().NextRound(); p.rnd() != nil {
				common.Logger.Infof("party %s: keygen round %d starting", p.rnd().Params().PartyID(), p.rnd().RoundNumber())
				if err := p.rnd().Start(); err != nil {
					return r(false, err)
				}
			}
			p.unlock()           // recursive so can't defer after return
			return p.Update(msg) // re-run round update or finish)
		}
		return r(true, nil)
	}
	// finished!
	common.Logger.Infof("party %s: keygen finished!", p.PartyID())
	p.finish()
	return r(true, nil)
}
