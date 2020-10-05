// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()
	bigVjs := make([]*crypto.ECPoint, len(round.Parties().IDs()))
	bigAjs := make([]*crypto.ECPoint, len(round.Parties().IDs()))
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		r4msg := round.temp.signRound4Messages[j].Content().(*SignRound4Message)
		cj, dj := r3msg.UnmarshalCommitment(), r4msg.UnmarshalDeCommitment()
		cmtDeCmt := commitments.HashCommitDecommit{C: cj, D: dj}
		ok, values := cmtDeCmt.DeCommit()
		if !ok || len(values) != 4 {
			return round.WrapError(errors.New("de-commitment for bigVj and bigAj failed"), Pj)
		}
		bigVjX, bigVjY, bigAjX, bigAjY := values[0], values[1], values[2], values[3]
		bigVj, err := crypto.NewECPoint(tss.EC(), bigVjX, bigVjY)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigVj)"), Pj)
		}
		bigVjs[j] = bigVj
		bigAj, err := crypto.NewECPoint(tss.EC(), bigAjX, bigAjY)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigAj)"), Pj)
		}
		bigAjs[j] = bigAj
		pijA, pijV, err := r4msg.UnmarshalZKProof()
		if err != nil {
			return round.WrapError(errors.New("fail to unmarshal the zk proof"), Pj)
		}
		if !pijA.Verify(bigAj) {
			return round.WrapError(errors.New("schnorr verify for Aj failed"), Pj)
		}

		if !pijV.Verify(bigVj) {
			return round.WrapError(errors.New("verify for Vj failed"), Pj)
		}
	}

	modN := common.ModInt(tss.EC().Params().N)
	hTest := encodedBytesToBigInt(&round.temp.h)
	minush := modN.Sub(zero, hTest)
	yminushx, yminusy := tss.EC().ScalarMult(round.key.EDDSAPub.X(), round.key.EDDSAPub.Y(), minush.Bytes())
	// y^(-h)*R(-1)
	m1x, m1y := tss.EC().Add(yminushx, yminusy, round.temp.bigMinusR.X(), round.temp.bigMinusR.Y())

	VX, VY := tss.EC().Add(m1x, m1y, round.temp.bigVi.X(), round.temp.bigVi.Y())

	AX, AY := round.temp.bigAi.X(), round.temp.bigAi.Y()

	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		VX, VY = tss.EC().Add(VX, VY, bigVjs[j].X(), bigVjs[j].Y())
		AX, AY = tss.EC().Add(AX, AY, bigAjs[j].X(), bigAjs[j].Y())
	}

	UiX, UiY := tss.EC().ScalarMult(VX, VY, round.temp.roi.Bytes())
	TiX, TiY := tss.EC().ScalarMult(AX, AY, round.temp.li.Bytes())
	round.temp.Ui = crypto.NewECPointNoCurveCheck(tss.EC(), UiX, UiY)
	round.temp.Ti = crypto.NewECPointNoCurveCheck(tss.EC(), TiX, TiY)
	cmt := commitments.NewHashCommitment(UiX, UiY, TiX, TiY)
	r5msg := NewSignRound5Message(round.PartyID(), cmt.C)
	round.temp.signRound5Messages[round.PartyID().Index] = r5msg
	round.out <- r5msg
	round.temp.DTelda = cmt.D
	return nil
}

func (round *round5) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound5Messages {
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

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound5Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round5) NextRound() tss.Round {
	round.started = false
	return &round6{round}
}
