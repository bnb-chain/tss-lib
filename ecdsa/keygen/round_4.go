// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"
	sync "sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	zkpsch "github.com/binance-chain/tss-lib/crypto/zkp/sch"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 5. Output 1. / Fig 6. Output 1.
	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			if ok := round.temp.r3msgpfmod[j].Verify(round.save.NTildej[j]); !ok {
				errChs <- round.WrapError(errors.New("proofMod verify failed"), Pj)
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			if ok := round.temp.r3msgpfprm[j].Verify(round.save.H1j[j], round.save.H2j[j], round.save.NTildej[j]); !ok {
				errChs <- round.WrapError(errors.New("proofPrm verify failed"), Pj)
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			share := vss.Share{
				Threshold: round.Threshold(),
				ID:        round.PartyID().KeyInt(),
				Share:     round.temp.r3msgxij[j],
			}
			if ok := share.Verify(round.EC(), round.Threshold(), round.temp.r2msgVss[j]); !ok {
				errChs <- round.WrapError(errors.New("vss verify failed"), Pj)
			}

		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0)
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("round4: failed to verify proofs"), culprits...)
	}

	// Fig 5. Output 2. / Fig 6. Output 2.
	xi := new(big.Int).Set(round.temp.shares[i].Share)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		xi = new(big.Int).Add(xi, round.temp.r3msgxij[j])
	}
	round.save.Xi = new(big.Int).Mod(xi, round.EC().Params().N)

	Vc := make([]*crypto.ECPoint, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c]
	}

	{
		var err error
		culprits := make([]*tss.PartyID, 0)
		for j, Pj := range round.Parties().IDs() {
			if j == i {
				continue
			}
			PjVs := round.temp.r2msgVss[j]
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
		culprits := make([]*tss.PartyID, 0)
		for j, Pj := range round.Parties().IDs() {
			kj := Pj.KeyInt()
			BigXj := Vc[0]
			z := big.NewInt(1)
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
			round.save.BigXj[j] = BigXj
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), culprits...)
		}
	}

	// Compute and SAVE the ECDSA public key `y`
	ecdsaPubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(err)
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	common.Logger.Debugf("%s public key: %x", round.PartyID(), ecdsaPubKey)

	proof, err := zkpsch.NewProof(round.save.BigXj[i], round.save.Xi)
	if err != nil {
		return round.WrapError(err)
	}

	r4msg := NewKGRound4Message(round.PartyID(), proof)
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
	for j, msg := range round.temp.r4msgpf {
		if round.ok[j] {
			continue
		}
		if msg == nil {
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
