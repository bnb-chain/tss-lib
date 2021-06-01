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

	identityAbort := false
	var identifyingAbortCulprits []*tss.PartyID

	Pi := round.PartyID()
	i := Pi.Index

	if round.abortMta {
		identityAbort = true
		// we are the victim, we just report the culprits
		r3msg := round.temp.signRound3Messages[i].Content().(*SignRound3Message)
		abortItems := r3msg.GetAbort().GetItem()
		for _, el := range abortItems {
			node := round.Parties().IDs()[el.GetIndex()]
			identifyingAbortCulprits = append(identifyingAbortCulprits, node)
		}
	}

	modN := common.ModInt(tss.EC().Params().N)
	bigR := round.temp.gammaIG
	// deltaI := *round.temp.deltaI
	deltaSum := zero
	if !identityAbort {
		deltaSum = round.temp.deltaI
	}

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		r1msg2 := round.temp.signRound1Messages[j].Content().(*SignRound1Message)
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		r4msg := round.temp.signRound4Messages[j].Content().(*SignRound4Message)

		switch c := r3msg.GetContent().(type) {
		case *SignRound3Message_Success:
			// calculating delta^-1 (below)
			deltaJ := c.Success.GetDeltaI()
			deltaSum = modN.Add(deltaSum, new(big.Int).SetBytes(deltaJ))
		case *SignRound3Message_Abort:
			identityAbort = true
			for _, el := range c.Abort.GetItem() {
				var culpritIndex int32
				if !round.verifyReportedProof(int(el.GetIndex()), j) {
					culpritIndex = el.GetIndex()
				} else {
					culpritIndex = int32(j)
				}
				node := round.Parties().IDs()[culpritIndex]
				identifyingAbortCulprits = append(identifyingAbortCulprits, node)
			}
		}

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
	}

	if identityAbort {
		return round.WrapError(errors.New("the bobmid proof is incorrect"), identifyingAbortCulprits...)
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

	pdlWSlackWitness := zkp.PDLwSlackWitness{
		X: kI,
		R: round.temp.rAKI,
	}

	var pdlWSlackPfs []zkp.PDLwSlackProof
	for j, _ := range round.Parties().IDs() {
		if j == i {
			pdlWSlackPfs = append(pdlWSlackPfs, zkp.PDLwSlackProof{})
			continue
		}
		pdlWSlackStatement := zkp.PDLwSlackStatement{
			N:          round.key.PaillierSK.N,
			CipherText: round.temp.cAKI,
			Q:          bigRBarI,
			G:          bigR,
			H1:         round.key.H1j[j],
			H2:         round.key.H2j[j],
			NTilde:     round.key.NTildej[j],
		}

		pdlWSlackPf := zkp.NewPDLwSlackProof(pdlWSlackWitness, pdlWSlackStatement)
		pdlWSlackPfs = append(pdlWSlackPfs, pdlWSlackPf)
	}
	r5msg := NewSignRound5Message(Pi, bigRBarI, pdlWSlackPfs)
	round.temp.signRound5Messages[i] = r5msg
	round.out <- r5msg
	return nil
}

func (round *round5) verifyReportedProof(blamedNodeIndex, reporterIndex int) bool {
	r2msg := round.temp.signRound2Messages[blamedNodeIndex].Content().(*SignRound2Message)
	r1msg := round.temp.signRound1Messages[reporterIndex].Content().(*SignRound1Message)
	proofBob, err := r2msg.UnmarshalProofBob(reporterIndex)
	if err != nil {
		common.Logger.Errorf("fail to get the stored proofBob %v", err)
		return false
	}
	proofBobWc, err := r2msg.UnmarshalProofBobWC(reporterIndex)
	if err != nil {
		common.Logger.Errorf("fail to get the stored proofBobWc %v\n", err)
		return false
	}
	paillierPk := round.key.PaillierPKs[reporterIndex]
	h1j := round.key.H1j[reporterIndex]
	h2j := round.key.H2j[reporterIndex]

	NTilde := round.key.NTildej[reporterIndex]
	cBstore, cBstoreWc, err := r2msg.UnmarshalC(reporterIndex)
	if err != nil {
		return false
	}
	cB := new(big.Int).SetBytes(cBstore)
	cA := new(big.Int).SetBytes(r1msg.C)
	cBWc := new(big.Int).SetBytes(cBstoreWc)
	B := round.temp.bigWs[blamedNodeIndex]
	return proofBob.Verify(paillierPk, NTilde, h1j, h2j, cA, cB) && proofBobWc.Verify(paillierPk, NTilde, h1j, h2j, cA, cBWc, B)
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
