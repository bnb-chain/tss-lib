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

	"github.com/binance-chain/tss-lib/common"
	zkpenc "github.com/binance-chain/tss-lib/crypto/zkp/enc"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

var (
    zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
    return &round1{
        &base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
    if round.started {
        return round.WrapError(errors.New("round already started"))
    }

    round.number = 1
    round.started = true
    round.resetOK()

    i := round.PartyID().Index
	//round.ok[i] = true

    // Round 1. sample
    KShare := common.GetRandomPositiveInt(round.Params().EC().Params().N)
    GammaShare := common.GetRandomPositiveInt(round.Params().EC().Params().N)
    K, KNonce, err := round.key.PaillierSK.EncryptAndReturnRandomness(KShare)
    if err != nil {
        return round.WrapError(fmt.Errorf("paillier encryption failed"))
    }
    G, GNonce, err := round.key.PaillierSK.EncryptAndReturnRandomness(GammaShare)
    if err != nil {
        return round.WrapError(fmt.Errorf("paillier encryption failed"))
    }
    
    // Round 1. enc_proof
    for j, Pj := range round.Parties().IDs() {
        if j == i {
            continue
        }
		proof, err := zkpenc.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, K, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], KShare, KNonce)
		if err != nil {
			return round.WrapError(fmt.Errorf("ProofEnc failed: %v", err))
		}

		r1msg := NewSignRound1Message(Pj, round.PartyID(), K, G, proof)
		round.out <- r1msg
    }

    round.temp.KShare = KShare
    round.temp.GammaShare = GammaShare
	round.temp.G = G
	round.temp.K = K
    round.temp.KNonce = KNonce
    round.temp.GNonce = GNonce

	round.ok[i] = true
    return nil
}

func (round *round1) Update() (bool, *tss.Error) {
    for j, msg := range round.temp.signRound1Messages {
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

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
    if _, ok := msg.Content().(*SignRound1Message); ok {
        return !msg.IsBroadcast()
    }
    return false
}

func (round *round1) NextRound() tss.Round {
    round.started = false
    return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
    i := round.PartyID().Index

    xi := round.key.Xi
    ks := round.key.Ks
    BigXs := round.key.BigXj

    // adding the key derivation delta to the xi's
    // Suppose x has shamir shares x_0,     x_1,     ..., x_n
    // So x + D has shamir shares  x_0 + D, x_1 + D, ..., x_n + D
    mod := common.ModInt(round.Params().EC().Params().N)
    xi = mod.Add(round.temp.keyDerivationDelta, xi)
    round.key.Xi = xi

    if round.Threshold()+1 > len(ks) {
        return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
    }
    wi, BigWs := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, BigXs)

    round.temp.w = wi
    round.temp.BigWs = BigWs
    return nil
}
