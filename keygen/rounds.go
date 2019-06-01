package keygen

import (
	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/types"
)

type (
	round interface {
		params() *KGParameters
		start() error
		update(msg types.Message) (bool, error)
		canAccept(msg types.Message) bool
		canProceed() bool
		roundNumber() int
		nextRound() round
	}

	round1 struct {
		*KGParameters
		save    *LocalPartySaveData
		temp    *LocalPartyTempData
		out     chan<- types.Message
		started bool
	}
	round2 struct {
		*round1
		started bool
	}
	round3 struct {
		*round2
		started bool
	}
)

func (round *round1) params() *KGParameters {
	return round.KGParameters
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
