package regroup

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	PaillierModulusLen = 2048
	// RSA also 2048-bit modulus; two 1024-bit primes
	RSAModulusLen = 2048
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *LocalPartyTempData, out chan<- tss.Message) tss.Round {
	return &round1{
		&base{params, save, temp, out, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOk()

	_ = round.PartyID().Index

	// TODO implement round 1

	return nil
}

func (round *round1) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*DGRound1OldCommitteeCommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.dgRound1OldCommitteeCommitMessages {
		if round.ok[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
