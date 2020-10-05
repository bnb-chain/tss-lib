// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/sha512"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOK()

	// 1. init R
	Rpoint := round.temp.pointRi

	// 2-6. compute R
	i := round.PartyID().Index
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*SignRound2Message)
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
		ok, coordinates := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		if len(coordinates) != 2 {
			return round.WrapError(errors.New("length of de-commitment should be 2"))
		}

		Rj, err := crypto.NewECPoint(tss.EC(), coordinates[0], coordinates[1])
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}
		proof, err := r2msg.UnmarshalZKProof()
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Rj proof"), Pj)
		}
		ok = proof.Verify(Rj)
		if !ok {
			return round.WrapError(errors.New("failed to prove Rj"), Pj)
		}

		Rpoint, err = Rpoint.Add(Rj)
		if err != nil {
			return round.WrapError(errors.New("failed to add curve point"), Pj)
		}
	}

	Rx, Ry := tss.EC().ScalarMult(Rpoint.X(), Rpoint.Y(), big.NewInt(-1).Bytes())
	R := ecPointToExtendedElement(Rx, Ry)

	// 7. compute lambda
	var encodedR [32]byte
	R.ToBytes(&encodedR)
	encodedPubKey := ecPointToEncodedBytes(round.key.EDDSAPub.X(), round.key.EDDSAPub.Y())
	// h = hash512(k || A || M)
	h := sha512.New()
	h.Reset()
	h.Write(encodedR[:])
	h.Write(encodedPubKey[:])
	h.Write(round.temp.m.Bytes())

	var lambda [64]byte
	h.Sum(lambda[:0])
	var lambdaReduced [32]byte
	edwards25519.ScReduce(&lambdaReduced, &lambda)

	// 8. compute si
	var localS [32]byte
	edwards25519.ScMulAdd(&localS, &lambdaReduced, bigIntToEncodedBytes(round.temp.wi), bigIntToEncodedBytes(round.temp.ri))

	// clean up the secret and the ri
	round.temp.wi = zero
	round.temp.ri = zero
	// 9. generate the random value for share proof
	li := common.GetRandomPositiveInt(tss.EC().Params().N)                  // li
	roI := common.GetRandomPositiveInt(tss.EC().Params().N)                 // pi
	gToSi := crypto.ScalarBaseMult(tss.EC(), encodedBytesToBigInt(&localS)) // g^s_i
	liPoint := crypto.ScalarBaseMult(tss.EC(), li)

	// compute A_i=g^(ro_i)
	bigAi := crypto.ScalarBaseMult(tss.EC(), roI)
	// compute g^(li)g^(s_i)
	bigVi, err := gToSi.Add(liPoint)
	if err != nil {
		return round.WrapError(errors.Wrapf(err, "rToSi.Add(li)"))
	}

	cmt := commitments.NewHashCommitment(bigVi.X(), bigVi.Y(), bigAi.X(), bigAi.Y())
	r3msg := NewSignRound3Message(round.PartyID(), cmt.C)

	// calculate the R^(-1)
	minusOne := new(big.Int).Mod(big.NewInt(-1), tss.EC().Params().N)
	x, y := tss.EC().ScalarMult(Rpoint.X(), Rpoint.Y(), minusOne.Bytes())
	bigMinusR, err := crypto.NewECPoint(tss.EC(), x, y)
	if err != nil {
		return round.WrapError(errors.Wrapf(err, "cannot map the R-1 to curve"))
	}

	// 10. broadcast si to other parties
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	// 11. store r3 message pieces
	round.temp.si = &localS
	round.temp.r = encodedBytesToBigInt(&encodedR)
	round.temp.h = lambdaReduced
	round.temp.li = li
	round.temp.bigAi = bigAi
	round.temp.bigVi = bigVi
	round.temp.roi = roI
	round.temp.bigMinusR = bigMinusR
	round.temp.DPower = cmt.D
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
