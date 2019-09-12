package signing

import (
	"errors"

	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
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
	round.resetOK()

	R := crypto.ScalarBaseMult(tss.EC(), round.temp.gamma)
	for j, Pj := range round.Parties().IDs() {
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
		bigGammaJPoint, err := crypto.NewECPoint(tss.EC(), bigGammaJ[0], bigGammaJ[1])
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigGammaJ)"), Pj)
		}
		ok = round.temp.signRound4DecommitMessage[j].Proof.Verify(bigGammaJPoint)
		if !ok {
			return round.WrapError(errors.New("failed to proof bigGamma"), Pj)
		}
		R, err = R.Add(bigGammaJPoint)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "R.Add(bigGammaJ)"), Pj)
		}
	}
	R = R.ScalarMult(round.temp.thelta_inverse)
	N := tss.EC().Params().N
	modN := common.ModInt(N)
	r := R.X()
	si := modN.Add(modN.Mul(round.temp.m, round.temp.k), modN.Mul(r, round.temp.sigma))
	// TODO: clear temp.k, temp.w

	li := random.GetRandomPositiveInt(N)  // li
	roI := random.GetRandomPositiveInt(N) // pi
	rToSi := R.ScalarMult(si)
	liPoint := crypto.ScalarBaseMult(tss.EC(), li)
	bigAi := crypto.ScalarBaseMult(tss.EC(), roI)
	bigVi, err := rToSi.Add(liPoint)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "rToSi.Add(li)"))
	}

	cmt := commitments.NewHashCommitment(bigVi.X(), bigVi.Y(), bigAi.X(), bigAi.Y())
	r5msg := NewSignRound5CommitmentMessage(round.PartyID(), cmt.C)
	round.temp.signRound5CommitMessage[round.PartyID().Index] = &r5msg
	round.out <- r5msg

	round.temp.li = li
	round.temp.bigAi = bigAi
	round.temp.bigVi = bigVi
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
