package signing

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common/random"
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
	round.resetOk()

	RX, RY := tss.EC().ScalarBaseMult(round.temp.gamma.Bytes())
	R := crypto.NewECPoint(tss.EC(), RX, RY)
	for j, Pj := range round.Parties().Parties() {
		if j == round.PartyID().Index {
			continue
		}
		SCj := round.temp.signRound1CommitMessages[j].Commitment
		SDj := round.temp.signRound4DecommitMessage[j].Decommitment
		cmtDeCmt := commitments.HashCommitDecommit{C: SCj, D: SDj}
		ok, bigGammaJ := cmtDeCmt.DeCommit()
		if !ok || len(bigGammaJ) != 2 {
			return round.WrapError(errors.New("commitment verify failed"), Pj)
		}
		ok = round.temp.signRound4DecommitMessage[j].Proof.Verify(crypto.NewECPoint(tss.EC(), bigGammaJ[0], bigGammaJ[1]))
		if !ok {
			return round.WrapError(errors.New("failed to proof bigGamma"), Pj)
		}
		RXNew, RYNew := tss.EC().Add(R.X(), R.Y(), bigGammaJ[0], bigGammaJ[1])
		R = crypto.NewECPoint(tss.EC(), RXNew, RYNew)
	}
	finalRX, finalRY := tss.EC().ScalarMult(R.X(), R.Y(), round.temp.thelta_inverse.Bytes())
	R = crypto.NewECPoint(tss.EC(), finalRX, finalRY)
	r := new(big.Int).Mod(finalRX, tss.EC().Params().N)
	si := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(round.temp.m, round.temp.k), new(big.Int).Mul(r, round.temp.sigma)), tss.EC().Params().N)
	// TODO: clear temp.k, temp.w

	li := random.GetRandomPositiveInt(tss.EC().Params().N)  // li
	roI := random.GetRandomPositiveInt(tss.EC().Params().N) // pi
	rToSiX, rToSiY := tss.EC().ScalarMult(R.X(), R.Y(), si.Bytes())
	liX, liY := tss.EC().ScalarBaseMult(li.Bytes())
	bigViX, bigViY := tss.EC().Add(rToSiX, rToSiY, liX, liY)
	bigAiX, bigAiY := tss.EC().ScalarBaseMult(roI.Bytes())

	cmt := commitments.NewHashCommitment(bigViX, bigViY, bigAiX, bigAiY)
	r5msg := NewSignRound5CommitmentMessage(round.PartyID(), cmt.C)
	round.temp.signRound5CommitMessage[round.PartyID().Index] = &r5msg
	round.out <- r5msg

	round.temp.li = li
	round.temp.bigAi = crypto.NewECPoint(tss.EC(), bigAiX, bigAiY)
	round.temp.bigVi = crypto.NewECPoint(tss.EC(), bigViX, bigViY)
	round.temp.roi = roI
	round.temp.DPower = cmt.D
	round.temp.si = si
	round.temp.r = r
	round.temp.bigR = R

	return nil
}

func (round *round5) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound5CommitMessage {
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

func (round *round5) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*SignRound5CommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round5) NextRound() tss.Round {
	round.started = false
	return &round6{round}
	return nil
}
