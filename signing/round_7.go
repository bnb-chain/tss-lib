package signing

import (
	"errors"
	"fmt"
	"math/big"

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
	round.resetOk()

	bigVjs := make([]*crypto.ECPoint, len(round.Parties().Parties()))
	bigAjs := make([]*crypto.ECPoint, len(round.Parties().Parties()))
	for j, Pj := range round.Parties().Parties() {
		if j == round.PartyID().Index {
			continue
		}
		cj := round.temp.signRound5CommitMessage[j].Commitment
		dj := round.temp.signRound6DecommitMessage[j].Decommitment
		cmtDeCmt := commitments.HashCommitDecommit{C: cj, D: dj}
		ok, values := cmtDeCmt.DeCommit()
		if !ok || len(values) != 4 {
			return round.WrapError(errors.New("decommitment for bigVj and bigAj failed"), Pj)
		}
		bigVjX, bigVjY, bigAjX, bigAjY := values[0], values[1], values[2], values[3]
		bigVj := crypto.NewECPoint(tss.EC(), bigVjX, bigVjY)
		bigVjs[j] = bigVj
		bigAj := crypto.NewECPoint(tss.EC(), bigAjX, bigAjY)
		bigAjs[j] = bigAj
		fmt.Printf("[CONG] idx: %d, received idx: %d, V: (%s, %s), A: (%s, %s)\n", round.PartyID().Index, j, bigVjX.String(), bigVjY.String(), bigAjX.String(), bigAjY.String())
		pijA := round.temp.signRound6DecommitMessage[j].Proof
		pijV := round.temp.signRound6DecommitMessage[j].VProof
		if !pijA.Verify(bigAj) {
			return round.WrapError(errors.New("schnorr verify for Aj failed"), Pj)
		}
		if !pijV.Verify(bigVj, round.temp.bigR) {
			return round.WrapError(errors.New("vverify for Vj failed"), Pj)
		}
	}

	fmt.Printf("[cong] idx: %d, verify bigAi: (%s, %s), bigVi: (%s, %s)\n", round.PartyID().Index, round.temp.bigAi.X(), round.temp.bigAi.Y(), round.temp.bigVi.X(), round.temp.bigVi.Y())

	AX, AY := round.temp.bigAi.X(), round.temp.bigAi.Y()
	minusM := new(big.Int).Mod(new(big.Int).Sub(big.NewInt(0), round.temp.m), tss.EC().Params().N)
	gToMInvX, gToMInvY := tss.EC().ScalarBaseMult(minusM.Bytes())
	minusR := new(big.Int).Mod(new(big.Int).Sub(big.NewInt(0), round.temp.r), tss.EC().Params().N)
	yToRInvX, yToRInvY := tss.EC().ScalarMult(round.key.ECDSAPub.X(), round.key.ECDSAPub.Y(), minusR.Bytes())
	VX, VY := tss.EC().Add(gToMInvX, gToMInvY, yToRInvX, yToRInvY)
	VX, VY = tss.EC().Add(VX, VY, round.temp.bigVi.X(), round.temp.bigVi.Y())

	for j := range round.Parties().Parties() {
		if j == round.PartyID().Index {
			continue
		}
		VX, VY = tss.EC().Add(VX, VY, bigVjs[j].X(), bigVjs[j].Y())
		AX, AY = tss.EC().Add(AX, AY, bigAjs[j].X(), bigAjs[j].Y())
	}

	round.temp.VVV = crypto.NewECPoint(tss.EC(), VX, VY)
	UiX, UiY := tss.EC().ScalarMult(VX, VY, round.temp.roi.Bytes())
	TiX, TiY := tss.EC().ScalarMult(AX, AY, round.temp.li.Bytes())
	round.temp.Ui = crypto.NewECPoint(tss.EC(), UiX, UiY)
	round.temp.Ti = crypto.NewECPoint(tss.EC(), TiX, TiY)
	fmt.Printf("[CONG] idx: %d, generated: U: (%s, %s), T: (%s, %s)\n", round.PartyID().Index, UiX.String(), UiY.String(), TiX.String(), TiY.String())
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
