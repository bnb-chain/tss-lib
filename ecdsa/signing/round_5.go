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

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	modN := common.ModInt(tss.EC().Params().N)

	bigR := round.temp.gammaIG
	deltaI := *round.temp.deltaI
	deltaSum := &deltaI

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		r1msg2 := round.temp.signRound1Message2s[j].Content().(*SignRound1Message2)
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		r4msg := round.temp.signRound4Messages[j].Content().(*SignRound4Message)

		// calculating Big R
		SCj, SDj := r1msg2.UnmarshalCommitment(), r4msg.UnmarshalDeCommitment()
		cmtDeCmt := commitments.HashCommitDecommit{C: SCj, D: SDj}
		ok, bigGammaJ := cmtDeCmt.DeCommit()
		if !ok || len(bigGammaJ) != 2 {
			return round.WrapError(errors.New("commitment verify failed"), Pj)
		}
		bigGammaJPoint, err := crypto.NewECPoint(tss.EC(), bigGammaJ[0], bigGammaJ[1])
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigGammaJ)"), Pj)
		}
		round.temp.bigGammaJs[j] = bigGammaJPoint // used for identifying abort in round 7
		bigR, err = bigR.Add(bigGammaJPoint)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "bigR.Add(bigGammaJ)"), Pj)
		}

		// calculating delta^-1 (below)
		deltaJ := r3msg.GetDeltaI()
		deltaSum = modN.Add(deltaSum, new(big.Int).SetBytes(deltaJ))
	}

	// compute the multiplicative inverse delta mod q
	deltaInv := modN.Inverse(deltaSum)

	// compute R and Rdash_i
	bigR = bigR.ScalarMult(deltaInv)
	round.temp.BigR = bigR.ToProtobufPoint()
	r := bigR.X()

	// used in FinalizeGetOurSigShare
	round.temp.RSigmaI = modN.Mul(r, round.temp.sigmaI).Bytes()

	// all parties broadcast Rdash_i = k_i * R
	kI := new(big.Int).SetBytes(round.temp.KI)
	bigRBarI := bigR.ScalarMult(kI)

	// compute ZK proof of consistency between R_i and E_i(k_i)
	// ported from: https://git.io/Jf69a
	pdlWSlackStatement := zkp.PDLwSlackStatement{
		PK:         &round.key.PaillierSK.PublicKey,
		CipherText: round.temp.cAKI,
		Q:          bigRBarI,
		G:          bigR,
		H1:         round.key.H1i,
		H2:         round.key.H2i,
		NTilde:     round.key.NTildei,
	}
	pdlWSlackWitness := zkp.PDLwSlackWitness{
		SK: round.key.PaillierSK,
		X:  kI,
		R:  round.temp.rAKI,
	}
	pdlWSlackPf := zkp.NewPDLwSlackProof(pdlWSlackWitness, pdlWSlackStatement)

	r5msg := NewSignRound5Message(Pi, bigRBarI, &pdlWSlackPf)
	round.temp.signRound5Messages[i] = r5msg
	round.out <- r5msg
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
	return &round6{round, false}
}
