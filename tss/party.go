package tss

import (
	"sync"

	"github.com/binance-chain/tss-lib/common"
)

type Party interface {
	String() string
	PartyID() *PartyID
	Start() *Error
	Update(msg Message, phase string) (ok bool, err *Error)
	ValidateMessage(msg Message) (bool, *Error)
	StoreMessage(msg Message) (bool, *Error)
	Finish()
	Rnd() Round
	WaitingFor() []*PartyID
	Advance()
	Lock()
	Unlock()
}

type BaseParty struct {
	*Parameters
	Round Round
	mtx   sync.Mutex

	// messaging
	Out chan<- Message
}

func (p *BaseParty) Rnd() Round {
	return p.Round
}

func (p *BaseParty) Advance() {
	p.Round = p.Round.NextRound()
}

func (p *BaseParty) Lock() {
	p.mtx.Lock()
}

func (p *BaseParty) Unlock() {
	p.mtx.Unlock()
}

func (p *BaseParty) WaitingFor() []*PartyID {
	p.Lock()
	defer p.Unlock()
	return p.Round.WaitingFor()
}

func BaseUpdate(p Party, msg Message, phase string) (ok bool, err *Error) {
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	// need this mtx unlock hook, L137 is recursive so cannot use defer
	r := func(ok bool, err *Error) (bool, *Error) {
		p.Unlock()
		return ok, err
	}
	p.Lock() // data is written to P state below
	common.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
	if p.Rnd() != nil {
		common.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.Rnd().RoundNumber(), msg.String())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.Rnd() != nil {
		common.Logger.Debugf("party %s: %s round %d update", p.Rnd().Params().PartyID(), phase, p.Rnd().RoundNumber())
		if _, err := p.Rnd().Update(); err != nil {
			return r(false, err)
		}
		if p.Rnd().CanProceed() {
			if p.Advance(); p.Rnd() != nil {
				common.Logger.Infof("party %s: %s round %d starting", p.Rnd().Params().PartyID(), phase, p.Rnd().RoundNumber())
				if err := p.Rnd().Start(); err != nil {
					return r(false, err)
				}
			}
			p.Unlock()                       // recursive so can't defer after return
			return BaseUpdate(p, msg, phase) // re-run round update or finish)
		}
		return r(true, nil)
	}
	// finished!
	common.Logger.Infof("party %s: %s finished!", p.PartyID(), phase)
	p.Finish()
	return r(true, nil)
}
