package keygen

import (
	"fmt"

	"github.com/binance-chain/tss-lib/types"
)

// fundamental is an error that has a message and a stack, but no caller.
type keygenError struct {
	cause    error
	round    int
	victim   *types.PartyID
	culprits []*types.PartyID
}

func newError(err error, round int, victim *types.PartyID, culprits ...*types.PartyID) *keygenError {
	return &keygenError{cause: err, round: round, victim: victim, culprits: culprits}
}

func (err *keygenError) Cause() error { return err.cause }

func (err *keygenError) Round() int { return err.round }

func (err *keygenError) Victim() *types.PartyID { return err.victim }

func (err *keygenError) Culprits() []*types.PartyID { return err.culprits }

func (err *keygenError) Error() string {
	if err == nil {
		return "keygenError is nil"
	}
	if err.culprits != nil && len(err.culprits) > 0 {
		return fmt.Sprintf("party %s, round %d, culprits %s: %s", err.victim, err.round, err.culprits, err.cause.Error())
	}
	return fmt.Sprintf("party %s, round %d: %s", err.victim, err.round, err.cause.Error())
}
