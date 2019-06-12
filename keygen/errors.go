package keygen

import (
	"fmt"

	"github.com/binance-chain/tss-lib/types"
)

// fundamental is an error that has a message and a stack, but no caller.
type keygenError struct {
	cause   error
	round   int
	victim,
	culprit *types.PartyID
}

func newError(err error, round int, victim *types.PartyID, culprit *types.PartyID) *keygenError {
	return &keygenError{cause: err, round: round, victim: victim, culprit: culprit}
}

func (err *keygenError) Cause() error { return err.cause }

func (err *keygenError) Round() int { return err.round }

func (err *keygenError) Victim() *types.PartyID { return err.victim }

func (err *keygenError) Culprit() *types.PartyID { return err.culprit }

func (err *keygenError) Error() string {
	if err == nil {
		return "keygenError is nil"
	}
	if err.culprit != nil {
		return fmt.Sprintf("party %s, round %d, culprit %s: %s", err.victim, err.round, err.culprit, err.cause.Error())
	}
	return fmt.Sprintf("party %s, round %d: %s", err.victim, err.round, err.cause.Error())
}
