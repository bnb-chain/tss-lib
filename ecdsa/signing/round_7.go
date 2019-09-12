package signing

import (
	"errors"
	"math/big"

	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
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
		cj := round.temp.signRound5CommitMessage[j].Commitment
		dj := round.temp.signRound6DecommitMessage[j].Decommitment
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
		pijA := round.temp.signRound6DecommitMessage[j].Proof
		pijV := round.temp.signRound6DecommitMessage[j].VProof
		if !pijA.Verify(bigAj) {
			return round.WrapError(errors.New("schnorr verify for Aj failed"), Pj)
		}
		if !pijV.Verify(bigVj, round.temp.bigR) {
			return round.WrapError(errors.New("vverify for Vj failed"), Pj)
		}
	}

	modN := common.ModInt(tss.EC().Params().N)
	AX, AY := round.temp.bigAi.X(), round.temp.bigAi.Y()
	minusM := modN.Sub(big.NewInt(0), round.temp.m)
	gToMInvX, gToMInvY := tss.EC().ScalarBaseMult(minusM.Bytes())
	minusR := modN.Sub(big.NewInt(0), round.temp.r)
	yToRInvX, yToRInvY := tss.EC().ScalarMult(round.key.ECDSAPub.X(), round.key.ECDSAPub.Y(), minusR.Bytes())
	VX, VY := tss.EC().Add(gToMInvX, gToMInvY, yToRInvX, yToRInvY)
	VX, VY = tss.EC().Add(VX, VY, round.temp.bigVi.X(), round.temp.bigVi.Y())

	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		VX, VY = tss.EC().Add(VX, VY, bigVjs[j].X(), bigVjs[j].Y())
		AX, AY = tss.EC().Add(AX, AY, bigAjs[j].X(), bigAjs[j].Y())
	}

	var err error
	round.temp.VVV, err = crypto.NewECPoint(tss.EC(), VX, VY)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "NewECPoint(V)"))
	}
	UiX, UiY := tss.EC().ScalarMult(VX, VY, round.temp.roi.Bytes())
	TiX, TiY := tss.EC().ScalarMult(AX, AY, round.temp.li.Bytes())
	round.temp.Ui = crypto.NewECPointNoCurveCheck(tss.EC(), UiX, UiY)
	round.temp.Ti = crypto.NewECPointNoCurveCheck(tss.EC(), TiX, TiY)
	cmt := commitments.NewHashCommitment(UiX, UiY, TiX, TiY)
	r7msg := NewSignRound7CommitMessage(round.PartyID(), cmt.C)
	round.temp.signRound7CommitMessage[round.PartyID().Index] = &r7msg
	round.out <- r7msg
	round.temp.DTelda = cmt.D

	return nil
}

func (round *round7) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound7CommitMessage {
		if round.ok[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round7) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*SignRound7CommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round7) NextRound() tss.Round {
	round.started = false
	return &round8{round}
}
