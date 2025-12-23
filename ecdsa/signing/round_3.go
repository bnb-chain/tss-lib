// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"
	"sync"

	errorspkg "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	alphaIJs := make([]*big.Int, len(round.Parties().IDs()))
	muIJs := make([]*big.Int, len(round.Parties().IDs()))    // mod q'd
	muIJRecs := make([]*big.Int, len(round.Parties().IDs())) // raw recovered
	muRandIJ := make([]*big.Int, len(round.Parties().IDs()))

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		// Alice_end
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
			proofBob, err := r2msg.UnmarshalProofBob()
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalProofBob failed"), Pj)
				return
			}
			alphaIJ, err := mta.AliceEnd(
				round.key.PaillierPKs[i],
				proofBob,
				round.key.H1j[i],
				round.key.H2j[i],
				round.temp.c1Is[j],
				new(big.Int).SetBytes(r2msg.GetC1()),
				round.key.NTildej[i],
				round.key.PaillierSK)
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			alphaIJs[j] = alphaIJ
			round.temp.r5AbortData.AlphaIJ[j] = alphaIJ.Bytes()
		}(j, Pj)
		// Alice_end_wc
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
			proofBobWC, err := r2msg.UnmarshalProofBobWC()
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalProofBobWC failed"), Pj)
				return
			}
			muIJ, muIJRec, muIJRand, err := mta.AliceEndWC(
				round.key.PaillierPKs[i],
				proofBobWC,
				round.temp.bigWs[j],
				round.temp.c1Is[j],
				new(big.Int).SetBytes(r2msg.GetC2()),
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i],
				round.key.PaillierSK)
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			muIJs[j] = muIJ       // mod q'd
			muIJRecs[j] = muIJRec // raw recovered
			muRandIJ[j] = muIJRand
		}(j, Pj)
	}

	// consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to calculate Alice_end or Alice_end_wc"), culprits...)
	}
	// for identifying aborts in round 7: muIJs, revealed during Type 7 identified abort
	round.temp.r7AbortData.MuIJ = common.BigIntsToBytes(muIJRecs)
	round.temp.r7AbortData.MuRandIJ = common.BigIntsToBytes(muRandIJ)

	q := tss.EC().Params().N
	modN := common.ModInt(q)

	kI := new(big.Int).SetBytes(round.temp.KI)
	deltaI := modN.Mul(kI, round.temp.gammaI)
	sigmaI := modN.Mul(kI, round.temp.wI)

	// clear wI from temp memory
	round.temp.wI.Set(zero)
	round.temp.wI = zero

	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		beta := modN.Sub(zero, round.temp.vJIs[j])
		deltaI.Add(deltaI, alphaIJs[j].Add(alphaIJs[j], round.temp.betas[j]))
		sigmaI.Add(sigmaI, muIJs[j].Add(muIJs[j], beta))
		deltaI.Mod(deltaI, q)
		sigmaI.Mod(sigmaI, q)
	}
	// nil sensitive data for gc
	round.temp.betas, round.temp.vJIs = nil, nil

	// gg20: calculate T_i = g^sigma_i h^l_i
	lI := common.GetRandomPositiveInt(q)
	h, err := crypto.ECBasePoint2(tss.EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	hLI := h.ScalarMult(lI)
	gSigmaI := crypto.ScalarBaseMult(tss.EC(), sigmaI)
	TI, err := gSigmaI.Add(hLI)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	// gg20: generate the ZK proof of T_i, verified in ValidateBasic for the round 3 message
	tProof, err := zkp.NewTProof(TI, h, sigmaI, lI)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	round.temp.TI = TI
	round.temp.lI = lI
	round.temp.deltaI = deltaI
	round.temp.sigmaI = sigmaI

	r3msg := NewSignRound3Message(Pi, deltaI, TI, tProof)
	round.temp.signRound3Messages[i] = r3msg
	round.out <- r3msg
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
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
