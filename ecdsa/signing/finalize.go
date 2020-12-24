// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	TaskNameFinalize = "signing-finalize"
)

// -----
// One Round Finalization (async/offline)
// -----

// FinalizeGetOurSigShare is called in one-round signing mode after the online rounds have finished to compute s_i.
func FinalizeGetOurSigShare(state *SignatureData, msg *big.Int) (sI *big.Int) {
	data := state.GetOneRoundData()

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	kI, rSigmaI := new(big.Int).SetBytes(data.GetKI()), new(big.Int).SetBytes(data.GetRSigmaI())
	sI = modN.Add(modN.Mul(msg, kI), rSigmaI)
	return
}

// FinalizeGetOurSigShare is called in one-round signing mode to build a final signature given others' s_i shares and a msg.
// Note: each P in otherPs should correspond with that P's s_i at the same index in otherSIs.
func FinalizeGetAndVerifyFinalSig(
	state *SignatureData,
	pk *ecdsa.PublicKey,
	msg *big.Int,
	ourP *tss.PartyID,
	ourSI *big.Int,
	otherSIs map[*tss.PartyID]*big.Int,
) (*SignatureData, *btcec.Signature, *tss.Error) {
	if len(otherSIs) == 0 {
		return nil, nil, FinalizeWrapError(errors.New("len(otherSIs) == 0"), ourP)
	}
	data := state.GetOneRoundData()
	if data.GetT() != int32(len(otherSIs)) {
		return nil, nil, FinalizeWrapError(errors.New("len(otherSIs) != T"), ourP)
	}

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	bigR, err := crypto.NewECPoint(tss.EC(),
		new(big.Int).SetBytes(data.GetBigR().GetX()),
		new(big.Int).SetBytes(data.GetBigR().GetY()))
	if err != nil {
		return nil, nil, FinalizeWrapError(err, ourP)
	}

	r, s := bigR.X(), ourSI
	culprits := make([]*tss.PartyID, 0, len(otherSIs))
	for Pj, sJ := range otherSIs {
		bigRBarJBz := data.GetBigRBarJ()[Pj.Id]
		bigSJBz := data.GetBigSJ()[Pj.Id]
		if Pj == nil || bigRBarJBz == nil || bigSJBz == nil {
			return nil, nil, FinalizeWrapError(errors.New("in loop: Pj or map value s_i is nil"), Pj)
		}

		// prep for identify aborts in phase 7
		bigRBarJ, err := crypto.NewECPoint(tss.EC(),
			new(big.Int).SetBytes(bigRBarJBz.GetX()),
			new(big.Int).SetBytes(bigRBarJBz.GetY()))
		if err != nil {
			culprits = append(culprits, Pj)
			continue
		}
		bigSI, err := crypto.NewECPoint(tss.EC(),
			new(big.Int).SetBytes(bigSJBz.GetX()),
			new(big.Int).SetBytes(bigSJBz.GetY()))
		if err != nil {
			culprits = append(culprits, Pj)
			continue
		}

		// identify aborts of "type 8" in phase 7
		// verify that R^S_i = Rdash_i^m * S_i^r
		bigRBarIM, bigSIR, bigRSI := bigRBarJ.ScalarMult(msg), bigSI.ScalarMult(r), bigR.ScalarMult(sJ)
		bigRBarIMBigSIR, err := bigRBarIM.Add(bigSIR)
		if err != nil || !bigRSI.Equals(bigRBarIMBigSIR) {
			culprits = append(culprits, Pj)
			continue
		}

		s = modN.Add(s, sJ)
	}
	if 0 < len(culprits) {
		return nil, nil, FinalizeWrapError(errors.New("identify abort assertion fail in phase 7"), ourP, culprits...)
	}

	// Calculate Recovery ID: It is not possible to compute the public key out of the signature itself;
	// the Recovery ID is used to enable extracting the public key from the signature.
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	recId := 0
	if bigR.X().Cmp(N) > 0 {
		recId = 2
	}
	if bigR.Y().Bit(0) != 0 {
		recId |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(N, 1)
	if s.Cmp(secp256k1halfN) > 0 {
		s.Sub(N, s)
		recId ^= 1
	}

	ok := ecdsa.Verify(pk, msg.Bytes(), r, s)
	if !ok {
		return nil, nil, FinalizeWrapError(fmt.Errorf("signature verification 1 failed"), ourP)
	}

	// save the signature for final output
	signature := new(common.ECSignature)
	signature.R, signature.S = r.Bytes(), s.Bytes()
	signature.Signature = append(r.Bytes(), s.Bytes()...)
	signature.SignatureRecovery = []byte{byte(recId)}
	signature.M = msg.Bytes()
	state.Signature = signature

	btcecSig := &btcec.Signature{R: r, S: s}
	if ok = btcecSig.Verify(msg.Bytes(), (*btcec.PublicKey)(pk)); !ok {
		return nil, nil, FinalizeWrapError(fmt.Errorf("signature verification 2 failed"), ourP)
	}

	// SECURITY: to be safe the oneRoundData is no longer needed here and reuse of `r` can compromise the key
	state.OneRoundData = nil

	return state, btcecSig, nil
}

func FinalizeWrapError(err error, victim *tss.PartyID, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskNameFinalize, 8, victim, culprits...)
}

// -----
// Full Online Finalization &
// Identify Aborts of "Type 7"
// ------

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 8
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	Pi := round.PartyID()
	i := Pi.Index

	culprits := make([]*tss.PartyID, 0, len(round.temp.signRound6Messages))

	// Identifiable Abort Type 7 triggered during Phase 6 (GG20)
	if round.abortingT7 {
		common.Logger.Infof("round 8: Abort Type 7 code path triggered")
		q := tss.EC().Params().N
		kIs := make([][]byte, len(Ps))
		gMus := make([][]*crypto.ECPoint, len(Ps))
		gNus := make([][]*crypto.ECPoint, len(Ps))
		gSigmaIPfs := make([]*zkp.ECDDHProof, len(Ps))
		for i := range gMus {
			gMus[i] = make([]*crypto.ECPoint, len(Ps))
		}
		for j := range gNus {
			gNus[j] = make([]*crypto.ECPoint, len(Ps))
		}
	outer:
		for j, msg := range round.temp.signRound7Messages {
			Pj := round.Parties().IDs()[j]
			var err error
			var paiPKJ *paillier.PublicKey
			if j == i {
				paiPKJ = &round.key.PaillierSK.PublicKey
			} else {
				paiPKJ = round.key.PaillierPKs[j]
			}

			r7msgInner, ok := msg.Content().(*SignRound7Message).GetContent().(*SignRound7Message_Abort)
			if !ok {
				common.Logger.Warnf("round 8: unexpected success message while in aborting mode: %+v", r7msgInner)
				culprits = append(culprits, Pj)
				continue
			}
			r7msg := r7msgInner.Abort

			// keep k_i and the g^sigma_i proof for later
			kIs[j] = r7msg.GetKI()
			if gSigmaIPfs[j], err = r7msg.UnmarshalSigmaIProof(); err != nil {
				culprits = append(culprits, Pj)
				continue
			}

			// content length sanity check
			// note: the len equivalence of each of the slices in this msg have already been checked in ValidateBasic(), so just look at the UIJ slice here
			if len(r7msg.GetMuIJ()) != len(Ps) {
				culprits = append(culprits, Pj)
				continue
			}

			// re-encrypt k_i to make sure it matches the one we have "on record"
			cA, err := paiPKJ.EncryptWithChosenRandomness(
				new(big.Int).SetBytes(r7msg.GetKI()),
				new(big.Int).SetBytes(r7msg.GetKRandI()))
			r1msg1 := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
			if err != nil || !bytes.Equal(cA.Bytes(), r1msg1.GetC()) {
				culprits = append(culprits, Pj)
				continue
			}

			mus := common.ByteSlicesToBigInts(r7msg.GetMuIJ())
			muRands := common.ByteSlicesToBigInts(r7msg.GetMuRandIJ())

			// check correctness of mu_i_j
			if muIJ, muRandIJ := mus[i], muRands[i]; j != i {
				cB, err := paiPKJ.EncryptWithChosenRandomness(muIJ, muRandIJ)
				if err != nil || !bytes.Equal(cB.Bytes(), round.temp.c2JIs[j].Bytes()) {
					culprits = append(culprits, Pj)
					continue outer
				}
			}
			// compute g^mu_i_j
			for k, mu := range mus {
				if k == j {
					continue
				}
				gMus[j][k] = crypto.ScalarBaseMult(tss.EC(), mu.Mod(mu, q))
			}
		}
		bigR := round.temp.rI
		if 0 < len(culprits) {
			goto fail
		}
		// compute g^nu_j_i's
		for i := range Ps {
			for j := range Ps {
				if j == i {
					continue
				}
				gWJKI := round.temp.bigWs[j].ScalarMultBytes(kIs[i])
				gNus[i][j], _ = gWJKI.Sub(gMus[i][j])
			}
		}
		// compute g^sigma_i's
		for i, P := range Ps {
			gWIMulKi := round.temp.bigWs[i].ScalarMultBytes(kIs[i])
			gSigmaI := gWIMulKi
			for j := range Ps {
				if j == i {
					continue
				}
				// add sum g^mu_i_j, sum g^nu_j_i
				gMuIJ, gNuJI := gMus[i][j], gNus[j][i]
				gSigmaI, _ = gSigmaI.Add(gMuIJ)
				gSigmaI, _ = gSigmaI.Add(gNuJI)
			}
			bigSI, _ := crypto.NewECPointFromProtobuf(round.temp.BigSJ[P.Id])
			if !gSigmaIPfs[i].VerifySigmaI(tss.EC(), gSigmaI, bigR, bigSI) {
				culprits = append(culprits, P)
				continue
			}
		}
	fail:
		return round.WrapError(errors.New("round 7 consistency check failed: y != bigSJ products, Type 7 identified abort, culprits known"), culprits...)
	}

	ourSI := round.temp.sI
	otherSIs := make(map[*tss.PartyID]*big.Int, len(Ps)-1)
	var multiErr error
	for j, msg := range round.temp.signRound7Messages {
		if j == i {
			continue
		}
		Pj := round.Parties().IDs()[j]
		r7msgInner, ok := msg.Content().(*SignRound7Message).GetContent().(*SignRound7Message_SI)
		if !ok {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, fmt.Errorf("round 8: unexpected abort message while in success mode: %+v", r7msgInner))
			continue
		}
		sI := r7msgInner.SI
		otherSIs[Pj] = new(big.Int).SetBytes(sI)
	}
	if 0 < len(culprits) {
		return round.WrapError(multiErr, culprits...)
	}

	pk := &ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     round.key.ECDSAPub.X(),
		Y:     round.key.ECDSAPub.Y(),
	}
	data, _, err := FinalizeGetAndVerifyFinalSig(round.data, pk, round.temp.m, round.PartyID(), ourSI, otherSIs)
	if err != nil {
		return err
	}
	round.data = data
	round.end <- round.data
	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
