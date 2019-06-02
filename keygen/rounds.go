package keygen

import (
	"sync"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/types"
)

type (
	round interface {
		params() *KGParameters
		mutex() *sync.RWMutex
		start() error
		update() (bool, error)
		canAccept(msg types.Message) bool
		canProceed() bool
		nextRound() round
		roundNumber() int
	}

	round1 struct {
		*KGParameters
		save    *LocalPartySaveData
		temp    *LocalPartyTempData
		out     chan<- types.Message
		mtx     *sync.RWMutex
		ok      []bool // `ok` tracks parties which have been verified by update()
		started bool
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
)

var _ round = (*round1)(nil)
var _ round = (*round2)(nil)
var _ round = (*round3)(nil)

func (round *round1) params() *KGParameters {
	return round.KGParameters
}
func (round *round1) mutex() *sync.RWMutex {
	return round.mtx
}

// TODO maybe do this better
func (round *round1) wrapError(err error) error {
	return errors.Wrapf(err, "party %s, round %d", round.params().partyID, round.roundNumber())
}
func (round *round2) wrapError(err error) error {
	return errors.Wrapf(err, "party %s, round %d", round.params().partyID, round.roundNumber())
}
func (round *round3) wrapError(err error) error {
	return errors.Wrapf(err, "party %s, round %d", round.params().partyID, round.roundNumber())
}
