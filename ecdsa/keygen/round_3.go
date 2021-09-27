// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"fmt"
	"math/big"

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
	//round.ok[i] = true

	// Fig 5. Round 3.1 / Fig 6. Round 3.1
	// TODO check NTildej[j] >= 2**(8kappa)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		listToHash, err := crypto.FlattenECPoints(round.temp.r2msgVss[j])
		if err != nil {
			fmt.Println("fletten failed", i, j) //TODO
			return round.WrapError(err, Pj)
		}
		listToHash = append(listToHash, round.save.PaillierPKs[j].N, round.save.NTildej[j], round.save.H1j[j], round.save.H2j[j])
		VjHash := common.SHA512_256i(listToHash...)
		if VjHash.Cmp(round.temp.r1msgVHashs[j]) != 0 {
			return round.WrapError(errors.New("verify hash failed"), Pj)
		}
	}

	// Fig 5. Round 3.2 TODO / Fig 6. Round 3.2 TODO_proofs
	proofMod, err := zkpmod.NewProof(round.save.NTildei, round.save.SP, round.save.SQ)
	if err != nil {
		return round.WrapError(errors.New("create proofmod failed"))
	}
	Phi := new(big.Int).Mul(new(big.Int).Lsh(round.save.P, 1), new(big.Int).Lsh(round.save.Q, 1))
	proofPrm, err := zkpprm.NewProof(round.save.H1i, round.save.H2i, round.save.NTildei, Phi, round.save.Beta)
	if err != nil {
		return round.WrapError(errors.New("create proofPrm failed"))
	}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		Cij, err := round.save.PaillierPKs[j].Encrypt(round.temp.shares[j].Share)
		if err != nil {
			return round.WrapError(errors.New("encrypt error"))
		}
		

		r3msg := NewKGRound3Message(Pj, round.PartyID(), Cij, proofMod, proofPrm)

		round.temp.kgRound3Messages[j] = r3msg // TODO remove
		round.out <- r3msg
	}

	round.ok[i] = true
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
