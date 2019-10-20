// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"fmt"
)

// fundamental is an error that has a message and a stack, but no caller.
type Error struct {
	cause    error
	task     string
	round    int
	victim   *PartyID
	culprits []*PartyID
}

func NewError(err error, task string, round int, victim *PartyID, culprits ...*PartyID) *Error {
	return &Error{cause: err, task: task, round: round, victim: victim, culprits: culprits}
}

func (err *Error) Unwrap() error { return err.cause }

func (err *Error) Cause() error { return err.cause }

func (err *Error) Task() string { return err.task }

func (err *Error) Round() int { return err.round }

func (err *Error) Victim() *PartyID { return err.victim }

func (err *Error) Culprits() []*PartyID { return err.culprits }

func (err *Error) Error() string {
	if err == nil || err.cause == nil {
		return "Error is nil"
	}
	if err.culprits != nil && len(err.culprits) > 0 {
		return fmt.Sprintf("task %s, party %v, round %d, culprits %s: %s",
			err.task, err.victim, err.round, err.culprits, err.cause.Error())
	}
	return fmt.Sprintf("task %s, party %v, round %d: %s",
		err.task, err.victim, err.round, err.cause.Error())
}
