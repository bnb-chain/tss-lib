// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/crypto"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
    if round.started {
        return round.WrapError(errors.New("round already started"))
    }
    round.number = 2
    round.started = true
    round.resetOK()

    i := round.PartyID().Index
	//round.ok[i] = true

    // Round 2.1 verify enc_proof
    for j, Pj := range round.Parties().IDs() {
        if j == i {
            continue
        }
		r1msg := round.temp.signRound1Messages[j].Content().(*SignRound1Message)
		Kj := r1msg.UnmarshalK()
		proof, err := r1msg.UnmarshalEncProof()
		if err != nil {
			return round.WrapError(errors.New("round2: proofenc unmarshal failed"), Pj)
		}
		ok := proof.Verify(round.EC(), round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, Kj)
		if !ok {
			return round.WrapError(errors.New("round2: proofenc verify failed"), Pj)
		}
    }

    // Round 2.2
    BigGammaShare := crypto.ScalarBaseMult(round.Params().EC(), round.temp.GammaShare)
	g := crypto.ScalarBaseMult(round.EC(), big.NewInt(1)) // used in prooflogstar
    for j, Pj := range round.Parties().IDs() {
        if j == i {
            continue
        }

		r1msg := round.temp.signRound1Messages[j].Content().(*SignRound1Message)
		Kj := r1msg.UnmarshalK()

		DeltaMtA, err := NewMtA(round.EC(), Kj, round.temp.GammaShare, BigGammaShare, round.key.PaillierPKs[j], &round.key.PaillierSK.PublicKey, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
		if err != nil {
			return round.WrapError(errors.New("MtADelta failed"))
		}	

		ChiMtA, err := NewMtA(round.EC(), Kj, round.temp.w, round.temp.BigWs[i], round.key.PaillierPKs[j], &round.key.PaillierSK.PublicKey, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
		if err != nil {
			return round.WrapError(errors.New("MtAChi failed"))
		}

		ProofLogstar, err := zkplogstar.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.G, BigGammaShare, g ,round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.GammaShare, round.temp.GNonce)
		if err != nil {
			return round.WrapError(errors.New("prooflogstar failed"))
		}

		r2msg := NewSignRound2Message(Pj, round.PartyID(), BigGammaShare, DeltaMtA.Dji, DeltaMtA.Fji, ChiMtA.Dji, ChiMtA.Fji, DeltaMtA.Proofji, ChiMtA.Proofji, ProofLogstar)
		round.out <- r2msg

		round.temp.DeltaShareBetas[j] = DeltaMtA.Beta
		round.temp.ChiShareBetas[j] = ChiMtA.Beta
    }

	round.temp.BigGammaShare = BigGammaShare
	round.ok[i] = true
    return nil
}

func (round *round2) Update() (bool, *tss.Error) {
    for j, msg := range round.temp.signRound2Messages {
        if round.ok[j] {
            continue
        }
        if msg == nil || !round.CanAccept(msg) {
            return false, nil
        }
        round.ok[j] = true
    }
    return true, nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
    if _, ok := msg.Content().(*SignRound2Message); ok {
        return !msg.IsBroadcast()
    }
    return false
}

func (round *round2) NextRound() tss.Round {
    round.started = false
    return &round3{round}
}
