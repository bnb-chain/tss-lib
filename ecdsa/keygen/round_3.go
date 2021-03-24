// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"
	"sync"

	"github.com/hashicorp/go-multierror"
	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	PIdx := round.PartyID().Index

	// 2-3.
	Vc := make(vss.Vs, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c] // ours
	}

	// 4-11.
	type vssOut struct {
		unWrappedErr error
		pjVs         vss.Vs
	}
	chs := make([]chan vssOut, len(Ps))
	for i := range chs {
		if i == PIdx {
			continue
		}
		chs[i] = make(chan vssOut)
	}
	xShares := make([]*big.Int, len(Ps))
	itemLocker := &sync.Mutex{}
	var abortItems []*KGRound3Message_AbortDataEntry
	round.temp.recvEncryptedShares = make([]recvEncryptedShare, len(Ps))
	// we put ourselves in the array
	round.temp.recvEncryptedShares[PIdx] = round.temp.broadcastEncryptedShare
	xShares[PIdx] = new(big.Int).Set(round.temp.shares[PIdx].Share)
	for j := range Ps {
		if j == PIdx {
			continue
		}
		// 6-8.
		go func(j int, ch chan<- vssOut) {
			// 4-9.
			KGCj := round.temp.KGCs[j]
			r2msg := round.temp.kgRound2Messages[j].Content().(*KGRound2Message)
			KGDj := r2msg.UnmarshalDeCommitment()
			cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: KGDj}
			ok, flatPolyGs := cmtDeCmt.DeCommit()
			if !ok || flatPolyGs == nil {
				ch <- vssOut{errors.New("de-commitment verify failed"), nil}
				return
			}
			PjVs, err := crypto.UnFlattenECPoints(tss.EC(), flatPolyGs)
			if err != nil {
				ch <- vssOut{err, nil}
				return
			}
			encryptedShare := new(big.Int).SetBytes(r2msg.EncryptedShare[round.PartyID().Index])
			round.temp.recvEncryptedShares[j] = r2msg.EncryptedShare
			m, x, err := round.save.PaillierSK.DecryptAndRecoverRandomness(encryptedShare)
			if err != nil {
				common.Logger.Errorf("invalid paillier encrypted keys from index:%d with error %s", j, err.Error())
				abortEntry := KGRound3Message_AbortDataEntry{
					Index:  int32(j),
					ShareM: nil,
					ShareX: nil,
				}
				itemLocker.Lock()
				abortItems = append(abortItems, &abortEntry)
				itemLocker.Unlock()
				ch <- vssOut{errors.New("vss verify failed"), nil}
				return
			}
			PjShare := vss.Share{
				Threshold: round.Threshold(),
				ID:        round.PartyID().KeyInt(),
				Share:     m,
			}
			if ok = PjShare.Verify(round.Threshold(), PjVs); !ok {
				abortEntry := KGRound3Message_AbortDataEntry{
					Index:  int32(j),
					ShareM: m.Bytes(),
					ShareX: x.Bytes(),
				}
				itemLocker.Lock()
				abortItems = append(abortItems, &abortEntry)
				itemLocker.Unlock()
				ch <- vssOut{errors.New("vss verify failed"), nil}
				return
			}
			xShares[j] = m
			// (9) handled above
			ch <- vssOut{nil, PjVs}
		}(j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)
	vssResults := make([]vssOut, len(Ps))
	{
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			vssResults[j] = <-chs[j]
			// collect culprits to error out with
			if err := vssResults[j].unWrappedErr; err != nil {
				culprits = append(culprits, Pj)
			}
		}
		var multiErr error
		if len(culprits) > 0 {
			for _, vssResult := range vssResults {
				if vssResult.unWrappedErr == nil {
					continue
				}
				multiErr = multierror.Append(multiErr, vssResult.unWrappedErr)
			}
			// now we ask the next round to be in abort mode and prepare the abort information
			round.temp.vssAbortData = KGRound3Message_AbortData{
				Item: abortItems,
			}
			round.vssAbort = true
			r3msg := NewKGRound3MessageAbort(round.PartyID(), &round.temp.vssAbortData)
			round.temp.kgRound3Messages[PIdx] = r3msg
			round.out <- r3msg
			// not returning error here, we will handle that in abort mode.
			return nil
		}
	}
	{
		var err error
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			// 10-11.
			PjVs := vssResults[j].pjVs
			for c := 0; c <= round.Threshold(); c++ {
				Vc[c], err = Vc[c].Add(PjVs[c])
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding PjVs[c] to Vc[c] resulted in a point not on the curve"), culprits...)
		}
	}

	// 1,9. calculate xi (deferred for performance)
	modQ := common.ModInt(tss.EC().Params().N)
	// xi := new(big.Int).Set(round.temp.shares[PIdx].Share)
	xi := big.NewInt(0)
	for _, share := range xShares {
		xi = xi.Add(xi, share)
	}
	round.save.Xi = modQ.Add(xi, zero)

	// 12-16. compute Xj for each Pj
	{
		var err error
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		bigXj := round.save.BigXj
		for j := 0; j < round.PartyCount(); j++ {
			Pj := round.Parties().IDs()[j]
			kj := Pj.KeyInt()
			BigXj := Vc[0]
			z := new(big.Int).SetInt64(int64(1))
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
			bigXj[j] = BigXj
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), culprits...)
		}
		round.save.BigXj = bigXj
	}

	// 17. compute and SAVE the ECDSA public key `y`
	ecdsaPubKey, err := crypto.NewECPoint(tss.EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "public key is not on the curve"))
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	common.Logger.Debugf("%s public key: %x", round.PartyID(), ecdsaPubKey)

	// BROADCAST paillier proof for Pi
	ki := round.PartyID().KeyInt()
	proof := round.save.PaillierSK.Proof(ki, ecdsaPubKey)
	r3msg := NewKGRound3MessageSuccessful(round.PartyID(), proof)
	round.temp.kgRound3Messages[PIdx] = r3msg
	round.out <- r3msg
	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// proof check is in round 4
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
