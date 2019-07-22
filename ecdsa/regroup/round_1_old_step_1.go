package regroup

import (
	"errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.ReGroupParameters, key, save *keygen.LocalPartySaveData, temp *LocalPartyTempData, out chan<- tss.Message) tss.Round {
	return &round1{
		&base{params, key, save, temp, out, make([]bool, len(params.NewParties().IDs())), make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allNewOK()

	if round.ReGroupParams().IsNewCommittee() {
		return nil
	}

	// 1.
	newIds := round.NewParties().IDs().Keys()
	vi, shares, err := vss.Create(round.NewThreshold(), round.key.Xi, newIds)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 2.
	pGFlat, err := crypto.FlattenECPoints(vi)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	cmt := cmt.NewHashCommitment(pGFlat...)

	// 3. populate temp data
	round.temp.Di = cmt.D
	round.temp.NewShares = shares
	round.temp.BigXs = round.key.BigXj

	// 4. "broadcast" C_i to members of the NEW committee
	r1msg := NewDGRound1OldCommitteeCommitMessage(round.NewParties().IDs(), round.PartyID(), cmt.C)
	round.out <- r1msg

	return nil
}

func (round *round1) CanAccept(msg tss.Message) bool {
	// accept messages from old -> new committee
	if msg, ok := msg.(*DGRound1OldCommitteeCommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round1) Update() (bool, *tss.Error) {
	// only the new committee receive in this round
	if round.ReGroupParams().IsOldCommittee() {
		return true, nil
	}
	// accept messages from old -> new committee
	for j, msg := range round.temp.dgRound1OldCommitteeCommitMessages {
		if round.oldOK[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		round.oldOK[j] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	common.Logger.Infof("NextRound() called on %v", round.PartyID())
	round.started = false
	return &round2{round}
}
