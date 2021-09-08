// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	// "sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
    if round.started {
        return round.WrapError(errors.New("round already started"))
    }
    round.number = 3
    round.started = true
    round.resetOK()

    i := round.PartyID().Index
    //round.ok[i] = true

    // Round 3.1
    g := crypto.ScalarBaseMult(round.EC(), big.NewInt(1)) // used in prooflogstar
    for j := range round.Parties().IDs() {
        if j == i {
            continue
        }
        r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
        DeltaD := r2msg.UnmarshalDjiDelta()
        DeltaF := r2msg.UnmarshalFjiDelta()
        proofAffgDelta, err := r2msg.UnmarshalAffgProofDelta(round.EC())
        if err != nil {
            return round.WrapError(errors.New("failed to unmarshal affg_delta in r2msg"))
        }
        BigGammaSharej := r2msg.UnmarshalBigGammaShare(round.EC())
        ok := proofAffgDelta.Verify(round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, DeltaD, DeltaF, BigGammaSharej)
        if !ok {
            return round.WrapError(errors.New("failed to verify affg delta @56"))
        }
        round.temp.DeltaShareAlphas[j], err = round.key.PaillierSK.Decrypt(DeltaD)
        if err != nil {
            return round.WrapError(errors.New("failed to do mta"))
        }
        ChiD := r2msg.UnmarshalDjiChi()
        ChiF := r2msg.UnmarshalFjiChi()
        proofAffgChi, err := r2msg.UnmarshalAffgProofChi(round.EC())
        if err != nil {
            return round.WrapError(errors.New("failed to unmarshal affg chi from r2msg"))
        }
        ok = proofAffgChi.Verify(round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, ChiD, ChiF, round.temp.BigWs[j])
        if !ok {
            return round.WrapError(errors.New("failed to verify affg chi"))
        }
        round.temp.ChiShareAlphas[j], err = round.key.PaillierSK.Decrypt(ChiD)
        if err != nil {
            return round.WrapError(errors.New("failed to do mta"))
        }

        proofLogstar, err := r2msg.UnmarshalLogstarProof(round.EC())
        if err != nil {
            return round.WrapError(errors.New("failed to verify logstar"))
            // return
        }
        r1msg := round.temp.signRound1Messages[j].Content().(*SignRound1Message)
        Gj := r1msg.UnmarshalG()
        ok = proofLogstar.Verify(round.EC(), round.key.PaillierPKs[j], Gj, BigGammaSharej, g, round.key.NTildei, round.key.H1i, round.key.H2i)
        if !ok {
            return round.WrapError(errors.New("failed to verify logstar"))
        }
    }

	// Round 3.2 
    BigGamma := round.temp.BigGammaShare
    for j := range round.Parties().IDs() {
        if j == i {
            continue
        }
        r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
        BigGamma, _ = BigGamma.Add(r2msg.UnmarshalBigGammaShare(round.EC()))
    }
    BigDeltaShare := BigGamma.ScalarMult(round.temp.KShare)

    modN := common.ModInt(round.EC().Params().N)
    DeltaShare := modN.Mul(round.temp.KShare, round.temp.GammaShare)
    ChiShare := modN.Mul(round.temp.KShare, round.temp.w)
    for j := range round.Parties().IDs() {
        if j == i {
            continue
        }
        DeltaShare = modN.Add(DeltaShare, round.temp.DeltaShareAlphas[j])
        DeltaShare = modN.Add(DeltaShare, round.temp.DeltaShareBetas[j])

        ChiShare = modN.Add(ChiShare, round.temp.ChiShareAlphas[j])
        ChiShare = modN.Add(ChiShare, round.temp.ChiShareBetas[j])
	}

	for j, Pj := range round.Parties().IDs() {
        if j == i {
            continue
        }
        ProofLogstar, err := zkplogstar.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, BigDeltaShare, BigGamma, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.KShare, round.temp.KNonce)
        if err != nil {
            return round.WrapError(errors.New("proof generation failed"))
        }

		r3msg := NewSignRound3Message(Pj, round.PartyID(), DeltaShare, BigDeltaShare, ProofLogstar)
        round.out <- r3msg
    }

    round.temp.DeltaShare = DeltaShare
    round.temp.ChiShare = ChiShare
    round.temp.BigDeltaShare = BigDeltaShare
    round.temp.BigGamma = BigGamma

	round.ok[i] = true
    return nil
}

func (round *round3) Update() (bool, *tss.Error) {
    for j, msg := range round.temp.signRound3Messages {
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

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
    if _, ok := msg.Content().(*SignRound3Message); ok {
        return !msg.IsBroadcast()
    }
    return false
}

func (round *round3) NextRound() tss.Round {
    round.started = false
    return &round4{round}
}
