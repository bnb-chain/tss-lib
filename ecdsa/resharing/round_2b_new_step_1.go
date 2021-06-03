// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/crypto/dlnp"
	"github.com/binance-chain/tss-lib/crypto/safeparameter"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2b) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allOldOK()

	if !round.ReSharingParams().IsNewCommittee() {
		round.allNewOK()
		return nil
	}

	Pi := round.PartyID()
	i := Pi.Index

	for j, msg := range round.temp.dgRound2aMessage1s {
		r0msg := msg.Content().(*DGRound2AMessage1)
		omega := new(big.Int).SetBytes(r0msg.Omega)
		round.temp.omegas[j] = omega
	}

	challenges, err := safeparameter.GenChallenges(round.save.NTildei, round.temp.omegas)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	paramProof, err := safeparameter.ProvePaiBlumPreParams(challenges, round.temp.omegas[i], round.save.LocalPreParams)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	preParams := round.save.LocalPreParams
	// generate the dlnproofs for resharing
	h1i, h2i, alpha, beta, p, q, NTildei :=
		preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.Beta,
		preParams.P,
		preParams.Q,
		preParams.NTildei
	dlnProof1 := dlnp.NewProof(h1i, h2i, alpha, p, q, NTildei)
	dlnProof2 := dlnp.NewProof(h2i, h1i, beta, p, q, NTildei)

	paillierPf := preParams.PaillierSK.Proof(Pi.KeyInt(), round.save.ECDSAPub)
	r2msg2, err := NewDGRound2bMessage1(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		&preParams.PaillierSK.PublicKey, paillierPf, preParams.NTildei, preParams.H1i, preParams.H2i, dlnProof1, dlnProof2, paramProof)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.temp.dgRound2bMessage1s[i] = r2msg2
	round.out <- r2msg2

	// for this P: SAVE de-commitments, paillier keys for round 2
	round.save.PaillierSK = preParams.PaillierSK
	round.save.PaillierPKs[i] = &preParams.PaillierSK.PublicKey
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i
	return nil
}

func (round *round2b) CanAccept(msg tss.ParsedMessage) bool {
	if round.ReSharingParams().IsNewCommittee() {
		if _, ok := msg.Content().(*DGRound2BMessage1); ok {
			return msg.IsBroadcast()
		}
	}

	return false
}

func (round *round2b) Update() (bool, *tss.Error) {
	if round.ReSharingParams().IsNewCommittee() {
		// accept messages from new -> new committee
		for j, msg := range round.temp.dgRound2bMessage1s {
			if round.newOK[j] {
				continue
			}
			if msg == nil || !round.CanAccept(msg) {
				return false, nil
			}
			round.newOK[j] = true
		}
	}

	return true, nil
}

func (round *round2b) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
