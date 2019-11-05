// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"errors"
	"fmt"
	"sync"

	"github.com/binance-chain/tss-lib/common"
)

type Party interface {
	Start() *Error
	// The main entry point when updating a party's state from the wire.
	// isBroadcast should represent whether the message was received via broadcast, and isToOldCommittee should only be true during re-sharing when a message was sent to the old committee.
	UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast, isToOldCommittee bool) (ok bool, err *Error)
	// You may use this entry point to update a party's state when running locally or in tests
	Update(msg ParsedMessage) (ok bool, err *Error)
	WaitingFor() []*PartyID
	ValidateMessage(msg ParsedMessage) (bool, *Error)
	StoreMessage(msg ParsedMessage) (bool, *Error)
	FirstRound() Round
	WrapError(err error, culprits ...*PartyID) *Error
	PartyID() *PartyID
	String() string

	// Private lifecycle methods
	setRound(Round) *Error
	round() Round
	advance()
	lock()
	unlock()
}

type BaseParty struct {
	mtx        sync.Mutex
	rnd        Round
	FirstRound Round
}

func (p *BaseParty) WaitingFor() []*PartyID {
	p.lock()
	defer p.unlock()
	return p.rnd.WaitingFor()
}

func (p *BaseParty) WrapError(err error, culprits ...*PartyID) *Error {
	return p.rnd.WrapError(err, culprits...)
}

// an implementation of ValidateMessage that is shared across the different types of parties (keygen, signing, dynamic groups)
func (p *BaseParty) ValidateMessage(msg ParsedMessage) (bool, *Error) {
	if msg == nil || msg.Content() == nil {
		return false, p.WrapError(fmt.Errorf("received nil msg: %s", msg))
	}
	if msg.GetFrom() == nil {
		return false, p.WrapError(fmt.Errorf("received msg with nil sender: %s", msg))
	}
	if !msg.GetFrom().ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("received msg with an invalid sender: %+v", msg.GetFrom()))
	}
	if !msg.ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *BaseParty) String() string {
	return fmt.Sprintf("round: %d", p.round().RoundNumber())
}

// -----
// Private lifecycle methods

func (p *BaseParty) setRound(round Round) *Error {
	if p.rnd != nil {
		return p.WrapError(errors.New("a round is already set on this party"))
	}
	p.rnd = round
	return nil
}

func (p *BaseParty) round() Round {
	return p.rnd
}

func (p *BaseParty) advance() {
	p.rnd = p.rnd.NextRound()
}

func (p *BaseParty) lock() {
	p.mtx.Lock()
}

func (p *BaseParty) unlock() {
	p.mtx.Unlock()
}

// ----- //

func BaseStart(p Party, task string, prepare ...func(Round) *Error) *Error {
	p.lock()
	defer p.unlock()
	if p.PartyID() == nil || !p.PartyID().ValidateBasic() {
		return p.WrapError(fmt.Errorf("could not start. this party has an invalid PartyID: %+v", p.PartyID()))
	}
	if p.round() != nil {
		return p.WrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	round := p.FirstRound()
	if err := p.setRound(round); err != nil {
		return err
	}
	if 1 < len(prepare) {
		return p.WrapError(errors.New("too many prepare functions given to Start(); 1 allowed"))
	}
	if len(prepare) == 1 {
		if err := prepare[0](round); err != nil {
			return err
		}
	}
	common.Logger.Infof("party %s: %s round %d starting", p.round().Params().PartyID(), task, 1)
	defer func() {
		common.Logger.Debugf("party %s: %s round %d finished", p.round().Params().PartyID(), task, 1)
	}()
	return p.round().Start()
}

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p Party, msg ParsedMessage, task string) (ok bool, err *Error) {
	// fast-fail on an invalid message; do not lock the mutex yet
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	// lock the mutex. need this mtx unlock hook; L108 is recursive so cannot use defer
	r := func(ok bool, err *Error) (bool, *Error) {
		p.unlock()
		return ok, err
	}
	p.lock() // data is written to P state below
	common.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
	if p.round() != nil {
		common.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.round().RoundNumber(), msg.String())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.round() != nil {
		common.Logger.Debugf("party %s: %s round %d update", p.round().Params().PartyID(), task, p.round().RoundNumber())
		if _, err := p.round().Update(); err != nil {
			return r(false, err)
		}
		if p.round().CanProceed() {
			if p.advance(); p.round() != nil {
				if err := p.round().Start(); err != nil {
					return r(false, err)
				}
				rndNum := p.round().RoundNumber()
				common.Logger.Infof("party %s: %s round %d started", p.round().Params().PartyID(), task, rndNum)
			}
			p.unlock()                      // recursive so can't defer after return
			return BaseUpdate(p, msg, task) // re-run round update or finish)
		}
		return r(true, nil)
	}
	// finished! the round implementation will have sent the data through the `end` channel.
	common.Logger.Infof("party %s: %s finished!", p.PartyID(), task)
	return r(true, nil)
}
