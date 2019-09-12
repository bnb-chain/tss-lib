package tss

import (
	"fmt"
	"sync"

	"github.com/binance-chain/tss-lib/common"
)

type Party interface {
	String() string
	PartyID() *PartyID
	Start() *Error
	// The main entry point when updating a party's state from the wire
	UpdateFromBytes(wireBytes []byte, from *PartyID, to []*PartyID) (ok bool, err *Error)
	// You may use this entry point to update a party's state when running locally or in tests
	Update(msg ParsedMessage) (ok bool, err *Error)
	ValidateMessage(msg ParsedMessage) (bool, *Error)
	StoreMessage(msg ParsedMessage) (bool, *Error)
	Finish()
	Rnd() Round
	WaitingFor() []*PartyID
	Advance()
	Lock()
	Unlock()
	WrapError(err error, culprits ...*PartyID) *Error
}

type BaseParty struct {
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

func (p *BaseParty) WrapError(err error, culprits ...*PartyID) *Error {
	return p.Round.WrapError(err, culprits...)
}

// an implementation of ValidateMessage that is shared across the different types of parties (keygen, signing, dynamic groups)
func (p *BaseParty) ValidateMessage(msg ParsedMessage) (bool, *Error) {
	if msg == nil || msg.Content() == nil {
		return false, p.WrapError(fmt.Errorf("received nil msg: %s", msg))
	}
	if msg.GetFrom() == nil {
		return false, p.WrapError(fmt.Errorf("received msg with nil sender: %s", msg))
	}
	if !msg.ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

// ----- //

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p Party, msg ParsedMessage, phase string) (ok bool, err *Error) {
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	// need this mtx unlock hook; L108 is recursive so cannot use defer
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
				if err := p.Rnd().Start(); err != nil {
					return r(false, err)
				}
				rndNum := p.Rnd().RoundNumber()
				common.Logger.Infof("party %s: %s round %d started", p.Rnd().Params().PartyID(), phase, rndNum)
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
