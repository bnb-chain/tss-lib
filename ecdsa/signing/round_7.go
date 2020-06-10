// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round7) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	// Identifiable Abort mode triggered during Phase 5 (GG20)
	if round.aborting {
		culprits := make([]*tss.PartyID, 0, len(round.temp.signRound6Messages))
	outer:
		for j, msg := range round.temp.signRound6Messages {
			if j == i {
				continue
			}
			Pj := round.Parties().IDs()[j]
			r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
			r6msgInner, ok := msg.Content().(*SignRound6Message).GetContent().(*SignRound6Message_Abort)
			if !ok {
				common.Logger.Warningf("unexpected success message while in aborting mode: %+v", r6msgInner)
				culprits = append(culprits, Pj)
				continue
			}
			r6msg := r6msgInner.Abort

			// Check that value gamma_j (in MtA) is consistent with bigGamma_j that is de-committed in Phase 4
			gammaJ := new(big.Int).SetBytes(r6msg.GetGammaI())
			gammaJG := crypto.ScalarBaseMult(tss.EC(), gammaJ)
			if !gammaJG.Equals(round.temp.bigGammaJs[j]) {
				culprits = append(culprits, Pj)
				continue
			}

			kJ := new(big.Int).SetBytes(r6msg.GetKI())
			calcDeltaJ := modN.Mul(kJ, gammaJ)
			for k, a := range r6msg.GetAlphaIJ() {
				if k == j {
					continue
				}
				if a == nil {
					culprits = append(culprits, Pj)
					continue outer
				}
				calcDeltaJ = modN.Add(calcDeltaJ, new(big.Int).SetBytes(a))
			}
			for k, b := range r6msg.GetBetaJI() {
				if k == j {
					continue
				}
				if b == nil {
					culprits = append(culprits, Pj)
					continue outer
				}
				calcDeltaJ = modN.Add(calcDeltaJ, new(big.Int).SetBytes(b))
			}
			if expDeltaJ := new(big.Int).SetBytes(r3msg.GetDeltaI()); expDeltaJ.Cmp(calcDeltaJ) != 0 {
				culprits = append(culprits, Pj)
				continue
			}
		}
		return round.WrapError(errors.New("round 6 consistency check failed: g != R products, type 5 identified abort, culprits known"), culprits...)
	}

	// bigR is stored as bytes for the OneRoundData protobuf struct
	bigRX, bigRY := new(big.Int).SetBytes(round.temp.BigR.GetX()), new(big.Int).SetBytes(round.temp.BigR.GetY())
	bigR := crypto.NewECPointNoCurveCheck(tss.EC(), bigRX, bigRY)

	h, err := crypto.ECBasePoint2(tss.EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}

	bigSJ := make(map[string]*common.ECPoint, len(round.temp.signRound6Messages))
	bigSJProducts := (*crypto.ECPoint)(nil)
	for j, msg := range round.temp.signRound6Messages {
		Pj := round.Parties().IDs()[j]
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		r6msgInner, ok := msg.Content().(*SignRound6Message).GetContent().(*SignRound6Message_Success)
		if !ok {
			return round.WrapError(fmt.Errorf("unexpected abort message while in success mode: %+v", r6msgInner), Pj)
		}
		r6msg := r6msgInner.Success

		TI, err := r3msg.UnmarshalTI()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		bigSI, err := r6msg.UnmarshalSI()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		bigSJ[Pj.Id] = bigSI.ToProtobufPoint()

		// ZK STProof check
		stProof, err := r6msg.UnmarshalSTProof()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		if ok := stProof.Verify(bigSI, TI, bigR, h); !ok {
			return round.WrapError(errors.New("STProof verify failure"), Pj)
		}

		// bigSI consistency check
		if bigSJProducts == nil {
			bigSJProducts = bigSI
			continue
		}
		if bigSJProducts, err = bigSJProducts.Add(bigSI); err != nil {
			return round.WrapError(err, Pj)
		}
	}
	{
		y := round.key.ECDSAPub
		if bigSJProducts.X().Cmp(y.X()) != 0 || bigSJProducts.Y().Cmp(y.Y()) != 0 {
			return round.WrapError(errors.New("consistency check failed; y != products"))
		}
	}
	round.temp.rI = bigR
	round.temp.BigSJ = bigSJ

	// PRE-PROCESSING FINISHED
	// If we are in one-round signing mode (msg is nil), we will exit out with the current state here and we are done.
	round.temp.T = int32(len(round.Parties().IDs()) - 1)
	round.data.OneRoundData = &round.temp.SignatureData_OneRoundData
	if round.temp.m == nil {
		round.end <- *round.data
		return nil
	}

	// Continuing the full online protocol.
	sI := FinalizeGetOurSigShare(round.data, round.temp.m)
	round.temp.sI = sI

	r7msg := NewSignRound7Message(round.PartyID(), sI)
	round.temp.signRound7Messages[i] = r7msg
	round.out <- r7msg
	return nil
}

func (round *round7) Update() (bool, *tss.Error) {
	// If we are in one-round signing mode (msg is nil) there are no further rounds.
	if round.temp.m == nil {
		return false, nil
	}
	// Continuing the full online protocol.
	for j, msg := range round.temp.signRound7Messages {
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

func (round *round7) CanAccept(msg tss.ParsedMessage) bool {
	// If we are in one-round signing mode (msg is nil) there are no further rounds.
	if round.temp.m == nil {
		return false
	}
	// Continuing the full online protocol.
	if _, ok := msg.Content().(*SignRound7Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round7) NextRound() tss.Round {
	// If we are in one-round signing mode (msg is nil), we will exit out with the current state here and there are no further rounds.
	if round.temp.m == nil {
		return nil
	}
	// Continuing the full online protocol.
	round.started = false
	return &finalization{round}
}
