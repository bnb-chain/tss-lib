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
	"github.com/binance-chain/tss-lib/tss"

	zkpmod "github.com/binance-chain/tss-lib/crypto/zkp/mod"
	zkpprm "github.com/binance-chain/tss-lib/crypto/zkp/prm"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	Pi := round.Parties().IDs()[i]
	round.ok[i] = true

	// Fig 5. Round 3.1 / Fig 6. Round 3.1
	toCmp := new(big.Int).Lsh(big.NewInt(1), 1024)
	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			if round.save.NTildej[j].Cmp(toCmp) < 0 {
				errChs <- round.WrapError(errors.New("paillier-blum modulus too small"), Pj)
			}
			listToHash, err := crypto.FlattenECPoints(round.temp.r2msgVss[j])
			if err != nil {
				errChs <- round.WrapError(err, Pj)
			}
			listToHash = append(listToHash, round.save.PaillierPKs[j].N, round.save.NTildej[j], round.save.H1j[j], round.save.H2j[j])
			VjHash := common.SHA512_256i(listToHash...)
			if VjHash.Cmp(round.temp.r1msgVHashs[j]) != 0 {
				errChs <- round.WrapError(errors.New("verify hash failed"), Pj)
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
		return round.WrapError(errors.New("round3: failed stage 3.1"), culprits...)
	}

	// Fig 5. Round 3.2 / Fig 6. Round 3.2
	SP := new(big.Int).Add(new(big.Int).Lsh(round.save.P, 1), big.NewInt(1))
	SQ := new(big.Int).Add(new(big.Int).Lsh(round.save.Q, 1), big.NewInt(1))
	proofMod, err := zkpmod.NewProof(round.save.NTildei, SP, SQ)
	if err != nil {
		return round.WrapError(errors.New("create proofmod failed"))
	}
	Phi := new(big.Int).Mul(new(big.Int).Lsh(round.save.P, 1), new(big.Int).Lsh(round.save.Q, 1))
	proofPrm, err := zkpprm.NewProof(round.save.H1i, round.save.H2i, round.save.NTildei, Phi, round.save.Beta)
	if err != nil {
		return round.WrapError(errors.New("create proofPrm failed"))
	}

	errChs = make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg = sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			Cij, err := round.save.PaillierPKs[j].Encrypt(round.temp.shares[j].Share)
			if err != nil {
				errChs <- round.WrapError(errors.New("encrypt error"), Pi)
			}
			
			r3msg := NewKGRound3Message(Pj, round.PartyID(), Cij, proofMod, proofPrm)
			round.out <- r3msg
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound3Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r3msgxij {
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

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
