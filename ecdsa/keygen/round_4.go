// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/hashicorp/go-multierror"
	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs() // TODO change Ps
	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 5. Output 2. / Fig 6. Output 2.
	xi := new(big.Int).Set(round.temp.shares[i].Share)
	for j := range Ps {
		if j == i {
			continue
		}
		xi = new(big.Int).Add(xi, round.temp.r3msgxij[j])
	}
	round.save.Xi = new(big.Int).Mod(xi, round.EC().Params().N)

	Vc := make(vss.Vs, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.r2msgVss[i][c] // ours
	}

	type vssOut struct {
		unWrappedErr error
		pjVs         vss.Vs
	}
	chs := make([]chan vssOut, len(Ps))
	for j := range chs {
		if j == i {
			continue
		}
		chs[j] = make(chan vssOut)
	}
	for j := range Ps {
		if j == i {
			continue
		}
		go func(j int, ch chan<- vssOut) {
			PjVs := round.temp.r2msgVss[j]
			PjShare := vss.Share{
				Threshold: round.Threshold(),
				ID:        round.PartyID().KeyInt(),
				Share:     round.temp.r3msgxij[j],
			}
			if ok := PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok {
				ch <- vssOut{errors.New("vss verify failed"), nil}
				return
			}
			ch <- vssOut{nil, PjVs}
		}(j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)
	vssResults := make([]vssOut, len(Ps))
	{
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == i {
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
			return round.WrapError(multiErr, culprits...)
		}
	}
	{
		var err error
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == i {
				continue
			}
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

	{
		var err error
		modQ := common.ModInt(round.EC().Params().N)
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

	// Compute and SAVE the ECDSA public key `y`
	ecdsaPubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "public key is not on the curve"))
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	common.Logger.Debugf("%s public key: %x", round.PartyID(), ecdsaPubKey)

	// BROADCAST paillier proof for Pi
	ki := round.PartyID().KeyInt()
	proof := round.save.PaillierSK.Proof(ki, ecdsaPubKey)
	r4msg := NewKGRound4Message(round.PartyID(), proof)
	round.temp.kgRound3Messages[i] = r4msg
	round.out <- r4msg
	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound4Messages {
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

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &roundout{round}
}
