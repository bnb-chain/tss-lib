package keygen

import (
	"github.com/binance-chain/tss-lib/types"
)

type (
	round interface {
		params() *KGParameters
		start() *keygenError
		update() (bool, *keygenError)
		canAccept(msg types.Message) bool
		canProceed() bool
		nextRound() round
		roundNumber() int
		wrapError(err error, culprit *types.PartyID) *keygenError
	}

	// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
	base struct {
		*KGParameters
		save    *LocalPartySaveData
		temp    *LocalPartyTempData
		out     chan<- types.Message
		ok      []bool // `ok` tracks parties which have been verified by update()
		started bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	round4 struct {
		*round3
	}
)

var _ round = (*round1)(nil)
var _ round = (*round2)(nil)
var _ round = (*round3)(nil)
var _ round = (*round4)(nil)

// ----- //

func (round *base) params() *KGParameters {
	return round.KGParameters
}

func (round *base) roundNumber() int {
	return round.number
}

// canProceed is inherited by other rounds
func (round *base) canProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// `ok` tracks parties which have been verified by update()
func (round *base) resetOk() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

func (round *base) wrapError(err error, culprit *types.PartyID) *keygenError {
	return newError(err, round.number, round.partyID, culprit)
}
