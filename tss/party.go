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

	"github.com/bnb-chain/tss-lib/v4/common"
)

type Party interface {
	Start() *Error
	// The main entry point when updating a party's state from the wire.
	// isBroadcast should represent whether the message was received via a reliable broadcast
	UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast bool) (ok bool, err *Error)
	// You may use this entry point to update a party's state when running locally or in tests
	Update(msg ParsedMessage) (ok bool, err *Error)
	Running() bool
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
	abort(*Error) *Error
	abortedWith() *Error
	lock()
	unlock()
}

type BaseParty struct {
	mtx        sync.Mutex
	rnd        Round
	FirstRound Round
	// aborted holds the first error that ended this party's participation, or
	// nil while it is still running. Guarded by mtx.
	//
	// Without it a party that has aborted keeps advancing. BaseUpdate stores
	// each message and re-runs the round regardless of what happened last time,
	// so a message pump that does not stop on the first error walks the party
	// into rounds whose predecessor never finished, reading the slots that
	// predecessor was supposed to fill. Those reads are not guarded -- they are
	// ordinary indexing of pre-allocated slices holding nil -- so the party
	// faults instead of reporting, with no error, no round number and no
	// culprit. The abort itself was reported correctly one message earlier; what
	// is lost is everything after it.
	aborted *Error
}

func (p *BaseParty) Running() bool {
	return p.rnd != nil
}

func (p *BaseParty) WaitingFor() []*PartyID {
	p.lock()
	defer p.unlock()
	if p.rnd == nil {
		return []*PartyID{}
	}
	return p.rnd.WaitingFor()
}

func (p *BaseParty) WrapError(err error, culprits ...*PartyID) *Error {
	if p.rnd == nil {
		return NewError(err, "", -1, nil, culprits...)
	}
	return p.rnd.WrapError(err, culprits...)
}

// an implementation of ValidateMessage that is shared across the different types of parties (keygen, signing, dynamic groups)
func (p *BaseParty) ValidateMessage(msg ParsedMessage) (bool, *Error) {
	if msg == nil || msg.Content() == nil {
		return false, p.WrapError(fmt.Errorf("received nil msg: %s", msg))
	}
	if msg.GetFrom() == nil || !msg.GetFrom().ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("received msg with an invalid sender: %s", msg))
	}
	if !msg.ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *BaseParty) String() string {
	if rnd := p.round(); rnd != nil {
		return fmt.Sprintf("round: %d", rnd.RoundNumber())
	}

	return "No more rounds"
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

// abort latches err as the reason this party stopped and returns it unchanged,
// so call sites can wrap a return in it without restructuring. Only the FIRST
// error is kept: it is the one that describes an actual protocol fault, while
// anything after it describes a party that should not have been running.
// Callers must hold the lock.
func (p *BaseParty) abort(err *Error) *Error {
	if err != nil && p.aborted == nil {
		p.aborted = err
	}
	return err
}

// abortedWith returns the latched error, or nil. Callers must hold the lock.
func (p *BaseParty) abortedWith() *Error {
	return p.aborted
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
			return p.abort(err)
		}
	}
	common.Logger.Infof("party %s: %s round %d starting", p.round().Params().PartyID(), task, 1)
	defer func() {
		common.Logger.Debugf("party %s: %s round %d finished", p.round().Params().PartyID(), task, 1)
	}()
	return p.abort(p.round().Start())
}

// IsSameMessage reports whether two ParsedMessage values carry identical
// content. Used by per-protocol StoreMessage implementations to distinguish
// legitimate at-least-once redelivery (same content, idempotent) from
// adversarial intra-session replacement (different content, must be
// rejected). Returns true if the wire-encoded bytes match exactly.
func IsSameMessage(a, b ParsedMessage) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a == b {
		return true
	}
	aBz, _, errA := a.WireBytes()
	bBz, _, errB := b.WireBytes()
	if errA != nil || errB != nil {
		return false
	}
	if len(aBz) != len(bBz) {
		return false
	}
	for i := range aBz {
		if aBz[i] != bBz[i] {
			return false
		}
	}
	return true
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
	// Refuse before storing anything. A party that has already reported an abort
	// is not a party that can be caught up by more messages; carrying on reads
	// the slots the failed round never filled. Reported with NO culprits: the
	// abort named whoever was responsible once already, and repeating that name
	// on every message the pump happens to deliver afterwards would let the
	// delivery rate decide how guilty a peer looks to a host that counts them.
	if aborted := p.abortedWith(); aborted != nil {
		return r(false, p.WrapError(fmt.Errorf(
			"this party aborted in round %d and cannot process further messages: %s",
			aborted.Round(), aborted.Cause())))
	}
	common.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
	if p.round() != nil {
		common.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.round().RoundNumber(), msg.String())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.round() != nil {
		common.Logger.Debugf("party %s: %s round %d update", p.round().Params().PartyID(), task, p.round().RoundNumber())
		// These two are latched, the rejections above are not. An error out of
		// Update or Start means a round touched this party's state and did not
		// finish it; a message that failed ValidateMessage or StoreMessage was
		// rejected before anything was written, and one bad message from one
		// peer must not end the party.
		if _, err := p.round().Update(); err != nil {
			return r(false, p.abort(err))
		}
		if p.round().CanProceed() {
			if p.advance(); p.round() != nil {
				if err := p.round().Start(); err != nil {
					return r(false, p.abort(err))
				}
				rndNum := p.round().RoundNumber()
				common.Logger.Infof("party %s: %s round %d started", p.round().Params().PartyID(), task, rndNum)
			} else {
				// finished! the round implementation will have sent the data through the `end` channel.
				common.Logger.Infof("party %s: %s finished!", p.PartyID(), task)
			}
			p.unlock()                      // recursive so can't defer after return
			return BaseUpdate(p, msg, task) // re-run round update or finish)
		}
		return r(true, nil)
	}
	return r(true, nil)
}
