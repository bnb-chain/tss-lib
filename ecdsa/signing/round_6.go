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

	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round6) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	bigR, _ := crypto.NewECPointFromProtobuf(round.temp.BigR)

	sigmaI := round.temp.sigmaI
	defer func() {
		round.temp.sigmaI.Set(zero)
		round.temp.sigmaI = zero
	}()

	errs := make(map[*tss.PartyID]error)
	bigRBarJProducts := (*crypto.ECPoint)(nil)
	BigRBarJ := make(map[string]*common.ECPoint, len(round.temp.signRound5Messages))
	for j, msg := range round.temp.signRound5Messages {
		Pj := round.Parties().IDs()[j]
		r5msg := msg.Content().(*SignRound5Message)
		bigRBarJ, err := r5msg.UnmarshalRI()
		if err != nil {
			errs[Pj] = err
			continue
		}
		BigRBarJ[Pj.Id] = bigRBarJ.ToProtobufPoint()

		// find products of all Rdash_i to ensure it equals the G point of the curve
		if bigRBarJProducts == nil {
			bigRBarJProducts = bigRBarJ
			continue
		}
		if bigRBarJProducts, err = bigRBarJProducts.Add(bigRBarJ); err != nil {
			errs[Pj] = err
			continue
		}

		if j == i {
			continue
		}
		// verify ZK proof of consistency between R_i and E_i(k_i)
		// ported from: https://git.io/Jf69a
		pdlWSlackPf, err := r5msg.UnmarshalPDLwSlackProof()
		if err != nil {
			errs[Pj] = err
			continue
		}
		r1msg1 := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
		pdlWSlackStatement := zkp.PDLwSlackStatement{
			PK:         round.key.PaillierPKs[Pj.Index],
			CipherText: new(big.Int).SetBytes(r1msg1.GetC()),
			Q:          bigRBarJ,
			G:          bigR,
			H1:         round.key.H1j[Pj.Index],
			H2:         round.key.H2j[Pj.Index],
			NTilde:     round.key.NTildej[Pj.Index], // maybe i
		}
		if !pdlWSlackPf.Verify(pdlWSlackStatement) {
			errs[Pj] = fmt.Errorf("failed to verify ZK proof of consistency between R_i and E_i(k_i) for P %d", j)
		}
	}
	if 0 < len(errs) {
		var multiErr error
		culprits := make([]*tss.PartyID, 0, len(errs))
		for Pj, err := range errs {
			multiErr = multierror.Append(multiErr, err)
			culprits = append(culprits, Pj)
		}
		return round.WrapError(multiErr, culprits...)
	}
	{
		ec := tss.EC()
		gX, gY := ec.Params().Gx, ec.Params().Gy
		if bigRBarJProducts.X().Cmp(gX) != 0 || bigRBarJProducts.Y().Cmp(gY) != 0 {
			round.abortingT5 = true
			common.Logger.Warnf("round 6: consistency check failed: g != R products, entering Type 5 identified abort")

			r6msg := NewSignRound6MessageAbort(Pi, &round.temp.r5AbortData)
			round.temp.signRound6Messages[i] = r6msg
			round.out <- r6msg
			return nil
		}
	}
	// wipe sensitive data for gc, not used from here
	round.temp.r5AbortData = SignRound6Message_AbortData{}

	round.temp.BigRBarJ = BigRBarJ

	// R^sigma_i proof used in type 7 aborts
	bigSI := bigR.ScalarMult(sigmaI)
	{
		sigmaPf, err := zkp.NewECSigmaIProof(tss.EC(), sigmaI, bigR, bigSI)
		if err != nil {
			return round.WrapError(err, Pi)
		}
		round.temp.r7AbortData.EcddhProofA1 = sigmaPf.A1.ToProtobufPoint()
		round.temp.r7AbortData.EcddhProofA2 = sigmaPf.A2.ToProtobufPoint()
		round.temp.r7AbortData.EcddhProofZ = sigmaPf.Z.Bytes()
	}

	h, err := crypto.ECBasePoint2(tss.EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	TI, lI := round.temp.TI, round.temp.lI
	stPf, err := zkp.NewSTProof(TI, bigR, h, sigmaI, lI)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	// wipe sensitive data for gc
	round.temp.lI.Set(zero)
	round.temp.TI, round.temp.lI = nil, nil

	r6msg := NewSignRound6MessageSuccess(Pi, bigSI, stPf)
	round.temp.signRound6Messages[i] = r6msg
	round.out <- r6msg
	return nil
}

func (round *round6) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound6Messages {
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

func (round *round6) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound6Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round6) NextRound() tss.Round {
	round.started = false
	return &round7{round, false}
}
