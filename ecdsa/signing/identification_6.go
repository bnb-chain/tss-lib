// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/common"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	zkpmul "github.com/binance-chain/tss-lib/crypto/zkp/mul"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func newRound6(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &identification6{&sign4{&presign3{&presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 3}}}}}}
}

func (round *identification6) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Output.2
	H, _ := round.key.PaillierSK.HomoMult(round.temp.KShare, round.temp.G)
	proofH, _ := zkpmul.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, round.temp.G, H, round.temp.KShare, round.temp.KNonce)
	DeltaShareEnc := H
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		DeltaShareEnc, _ = round.key.PaillierSK.HomoAdd(DeltaShareEnc, round.temp.r2msgDeltaD[j])
		DeltaShareEnc, _ = round.key.PaillierSK.HomoAdd(DeltaShareEnc, round.temp.DeltaMtAF)
	}

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		proofDeltaShare, _ := zkpdec.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, DeltaShareEnc, round.temp.DeltaShare, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.DeltaShare, round.temp.GNonce)
		
		r6msg := NewIdentificationRound6Message(Pj, round.PartyID(), H, proofH, DeltaShareEnc, proofDeltaShare)
		round.out <- r6msg
	}

	return nil
}

func (round *identification6) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r6msgH {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *identification6) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*IdentificationRound6Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *identification6) NextRound() tss.Round {
	round.started = false
	return &identification7{round}
}
