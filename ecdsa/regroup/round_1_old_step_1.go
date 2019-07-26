package regroup

import (
	"errors"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/tss"
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.ReGroupParameters, key, save *keygen.LocalPartySaveData, temp *LocalPartyTempData, out chan<- tss.Message) tss.Round {
	return &round1{
		&base{params, key, save, temp, out, make([]bool, params.Threshold()+1), make([]bool, len(params.NewParties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allNewOK()

	if !round.ReGroupParams().IsOldCommittee() {
		return nil
	}
	round.allOldOK()

	Pi := round.PartyID()
	i := Pi.Index

	// 1. PrepareForSigning() -> w_i
	xi := round.key.Xi
	ks := round.key.Ks
	bigXs := round.key.BigXj
	newKs := round.NewParties().IDs().Keys()
	wi, _ := signing.PrepareForSigning(i, round.Threshold()+1, xi, ks, round.key.BigXj)

	// 2.
	vi, shares, err := vss.Create(round.NewThreshold(), wi, newKs)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 3.
	flatVis, err := crypto.FlattenECPoints(vi)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// include "Big X's" and list of indexes (k_j) known by this party in the commitment
	flatBigXs, err := crypto.FlattenECPoints(bigXs)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	cBuilder := commitments.NewBuilder()
	secrets := cBuilder.AddPart(flatBigXs).AddPart(round.key.Ks).Secrets()
	cmtR := round.save.ECDSAPub.X()
	xAndKCmt := commitments.NewHashCommitmentWithRandomness(cmtR, secrets...)

	vCmt := commitments.NewHashCommitment(flatVis...)

	// 4. populate temp data
	round.temp.VD = vCmt.D
	round.temp.XAndKD = xAndKCmt.D
	round.temp.NewShares = shares

	// 5. "broadcast" C_i to members of the NEW committee
	r1msg := NewDGRound1OldCommitteeCommitMessage(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		round.save.ECDSAPub, vCmt.C, xAndKCmt.C)
	round.temp.dgRound1OldCommitteeCommitMessages[i] = &r1msg
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
	if !round.ReGroupParameters.IsNewCommittee() {
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

		// save the ecdsa pub received from the old committee
		candidate := round.temp.dgRound1OldCommitteeCommitMessages[0].ECDSAPub
		// TODO improve this ecdsa pubkey consistency check
		if round.save.ECDSAPub != nil &&
			candidate != round.save.ECDSAPub {
			// uh oh - anomaly!
			return false, round.WrapError(errors.New("ecdsa pub did not match what we received previously"), msg.GetFrom())
		}
		round.save.ECDSAPub = round.temp.dgRound1OldCommitteeCommitMessages[0].ECDSAPub
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
