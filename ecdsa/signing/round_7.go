// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	errors2 "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (round *round7) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.resetOK()

	bigVjs := make([]*crypto.ECPoint, len(round.Parties().IDs()))
	bigAjs := make([]*crypto.ECPoint, len(round.Parties().IDs()))
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		r5msg := round.temp.signRound5Messages[j].Content().(*SignRound5Message)
		r6msg := round.temp.signRound6Messages[j].Content().(*SignRound6Message)
		cj, dj := r5msg.UnmarshalCommitment(), r6msg.UnmarshalDeCommitment()
		cmtDeCmt := commitments.HashCommitDecommit{C: cj, D: dj}
		ok, values := cmtDeCmt.DeCommit()
		if !ok || len(values) != 4 {
			return round.WrapError(errors.New("de-commitment for bigVj and bigAj failed"), Pj)
		}
		bigVjX, bigVjY, bigAjX, bigAjY := values[0], values[1], values[2], values[3]
		bigVj, err := crypto.NewECPoint(round.Params().EC(), bigVjX, bigVjY)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigVj)"), Pj)
		}
		bigVjs[j] = bigVj
		bigAj, err := crypto.NewECPoint(round.Params().EC(), bigAjX, bigAjY)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigAj)"), Pj)
		}
		bigAjs[j] = bigAj
		pijA, err := r6msg.UnmarshalZKProof(round.Params().EC())
		if err != nil || !pijA.Verify(ContextJ, bigAj) {
			return round.WrapError(errors.New("schnorr verify for Aj failed"), Pj)
		}
		pijV, err := r6msg.UnmarshalZKVProof(round.Params().EC())
		if err != nil || !pijV.Verify(ContextJ, bigVj, round.temp.bigR) {
			return round.WrapError(errors.New("vverify for Vj failed"), Pj)
		}
	}

	modN := common.ModInt(round.Params().EC().Params().N)
	AX, AY := round.temp.bigAi.X(), round.temp.bigAi.Y()
	minusM := modN.Sub(big.NewInt(0), round.temp.m)
	gToMInvX, gToMInvY := round.Params().EC().ScalarBaseMult(minusM.Bytes())
	minusR := modN.Sub(big.NewInt(0), round.temp.rx)
	yToRInvX, yToRInvY := round.Params().EC().ScalarMult(round.key.ECDSAPub.X(), round.key.ECDSAPub.Y(), minusR.Bytes())
	VX, VY := round.Params().EC().Add(gToMInvX, gToMInvY, yToRInvX, yToRInvY)
	VX, VY = round.Params().EC().Add(VX, VY, round.temp.bigVi.X(), round.temp.bigVi.Y())

	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		VX, VY = round.Params().EC().Add(VX, VY, bigVjs[j].X(), bigVjs[j].Y())
		AX, AY = round.Params().EC().Add(AX, AY, bigAjs[j].X(), bigAjs[j].Y())
	}

	UiX, UiY := round.Params().EC().ScalarMult(VX, VY, round.temp.roi.Bytes())
	TiX, TiY := round.Params().EC().ScalarMult(AX, AY, round.temp.li.Bytes())
	round.temp.Ui = crypto.NewECPointNoCurveCheck(round.Params().EC(), UiX, UiY)
	round.temp.Ti = crypto.NewECPointNoCurveCheck(round.Params().EC(), TiX, TiY)
	cmt := commitments.NewHashCommitment(UiX, UiY, TiX, TiY)
	r7msg := NewSignRound7Message(round.PartyID(), cmt.C)
	round.temp.signRound7Messages[round.PartyID().Index] = r7msg
	round.out <- r7msg
	round.temp.DTelda = cmt.D

	return nil
}

func (round *round7) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound7Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round7) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound7Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round7) NextRound() tss.Round {
	round.started = false
	return &round8{round}
}
