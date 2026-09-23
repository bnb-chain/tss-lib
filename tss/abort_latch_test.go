// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A round that fails on demand, so BaseUpdate's latch can be exercised without a
// protocol behind it.
type latchTestRound struct {
	params     *Parameters
	number     int
	failUpdate bool
	updates    int
}

func (r *latchTestRound) Params() *Parameters { return r.params }
func (r *latchTestRound) RoundNumber() int    { return r.number }
func (r *latchTestRound) CanProceed() bool    { return false }
func (r *latchTestRound) NextRound() Round    { return nil }
func (r *latchTestRound) Start() *Error       { return nil }
func (r *latchTestRound) CanAccept(ParsedMessage) bool {
	return true
}
func (r *latchTestRound) WaitingFor() []*PartyID { return nil }
func (r *latchTestRound) WrapError(err error, culprits ...*PartyID) *Error {
	return NewError(err, "latch-test", r.number, r.params.PartyID(), culprits...)
}
func (r *latchTestRound) Update() (bool, *Error) {
	r.updates++
	if r.failUpdate {
		return false, r.WrapError(errors.New("round update failed"), r.params.PartyID())
	}
	return true, nil
}

// A party whose StoreMessage always succeeds, so the only thing that can end it
// is the round.
type latchTestParty struct {
	*BaseParty
	params *Parameters
	stored int
}

func (p *latchTestParty) Start() *Error { return nil }
func (p *latchTestParty) UpdateFromBytes([]byte, *PartyID, bool) (bool, *Error) {
	return false, nil
}
func (p *latchTestParty) Update(msg ParsedMessage) (bool, *Error) {
	return BaseUpdate(p, msg, "latch-test")
}
func (p *latchTestParty) StoreMessage(ParsedMessage) (bool, *Error) {
	p.stored++
	return true, nil
}
func (p *latchTestParty) FirstRound() Round { return p.BaseParty.FirstRound }
func (p *latchTestParty) PartyID() *PartyID { return p.params.PartyID() }
func (p *latchTestParty) ValidateMessage(msg ParsedMessage) (bool, *Error) {
	return p.BaseParty.ValidateMessage(msg)
}

// latchTestContent is a minimal MessageContent: any registered proto message
// plus a ValidateBasic that accepts, so the only thing that can end the party in
// these tests is the round.
type latchTestContent struct {
	*MessageWrapper_PartyID
}

func (c *latchTestContent) ValidateBasic() bool { return true }

func newLatchTestParty(failUpdate bool) (*latchTestParty, *latchTestRound, SortedPartyIDs) {
	ids := GenerateTestPartyIDs(2)
	params := NewParameters(S256(), NewPeerContext(ids), ids[0], 2, 1)
	rnd := &latchTestRound{params: params, number: 1, failUpdate: failUpdate}
	p := &latchTestParty{BaseParty: &BaseParty{}, params: params}
	p.BaseParty.rnd = rnd
	return p, rnd, ids
}

func latchTestMessage(from *PartyID) ParsedMessage {
	meta := MessageRouting{From: from, IsBroadcast: true}
	content := &latchTestContent{MessageWrapper_PartyID: &MessageWrapper_PartyID{Id: "x", Key: []byte{1}}}
	return NewMessage(meta, content, NewMessageWrapper(meta, content))
}

// Once a round has reported an abort, the party must stop. Feeding it more
// messages used to re-run the round machinery over state the failed round never
// finished, which is read without guards.
func TestAnAbortedPartyRefusesFurtherMessages(t *testing.T) {
	p, rnd, ids := newLatchTestParty(true)
	msg := latchTestMessage(ids[1])

	_, err := p.Update(msg)
	if !assert.NotNil(t, err, "the round's own failure must be reported") {
		return
	}
	assert.Contains(t, err.Cause().Error(), "round update failed")
	assert.Len(t, err.Culprits(), 1, "the original abort names who was responsible")
	assert.Equal(t, 1, rnd.updates)

	// Everything after it is refused, and refused without re-running the round.
	for i := 0; i < 3; i++ {
		_, err = p.Update(msg)
		if !assert.NotNil(t, err, "an aborted party must keep refusing") {
			return
		}
		assert.True(t, strings.Contains(err.Cause().Error(), "aborted in round 1"),
			"the refusal must say the party had already stopped, got: %v", err.Cause())
		assert.Contains(t, err.Cause().Error(), "round update failed",
			"and must carry the original reason")
		assert.Empty(t, err.Culprits(),
			"a repeated refusal must name nobody: the abort named them once, and "+
				"re-naming per delivered message lets the pump rate decide how guilty a peer looks")
	}
	assert.Equal(t, 1, rnd.updates, "the round must not be re-entered after it failed")
	assert.Equal(t, 1, p.stored, "nothing may be stored after the abort")
}

// Negative control. Latching on every error, or on the first message, would
// satisfy the test above just as well: a party whose round does not fail must
// keep accepting.
func TestARunningPartyKeepsAcceptingMessages(t *testing.T) {
	p, rnd, ids := newLatchTestParty(false)
	msg := latchTestMessage(ids[1])

	for i := 0; i < 3; i++ {
		ok, err := p.Update(msg)
		assert.Nil(t, err, "a running party must not be refused")
		assert.True(t, ok)
	}
	assert.Equal(t, 3, rnd.updates)
	assert.Equal(t, 3, p.stored)
}

// The latch covers errors from the round, which has written state, and not the
// rejections above it, which have not. One malformed message from one peer must
// not end a party's participation.
func TestARejectedMessageDoesNotAbortTheParty(t *testing.T) {
	p, rnd, ids := newLatchTestParty(false)

	_, err := p.Update(nil)
	assert.NotNil(t, err, "a nil message is rejected")

	ok, err := p.Update(latchTestMessage(ids[1]))
	assert.Nil(t, err, "the party must still be running after rejecting a message")
	assert.True(t, ok)
	assert.Equal(t, 1, rnd.updates)
}
