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

	"github.com/agl/ed25519/edwards25519"
	"github.com/bnb-chain/tss-lib/v4/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	sumS := round.temp.si
	// Edwards curve order L (= 2^252 + 27742317777372353535851937790883648493).
	L := round.Params().EC().Params().N
	for j, Pj := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		sj := r3msg.UnmarshalS()
		// Reject scalars outside [1, L-1] before they enter the silent
		// 32-byte truncation in bigIntToEncodedBytes. Attributes the
		// failure to the actual culprit Pj rather than producing an
		// opaque "signature verification failed" at the aggregate level.
		if sj.Sign() <= 0 || sj.Cmp(L) >= 0 {
			return round.WrapError(errors.New(
				"partial signature S out of range [1, L-1]"), Pj)
		}
		sjBytes := bigIntToEncodedBytes(sj)
		var tmpSumS [32]byte
		edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), sjBytes)
		sumS = &tmpSumS
	}
	s := encodedBytesToBigInt(sumS)

	// save the signature for final output
	round.data.Signature = append(bigIntToEncodedBytes(round.temp.r)[:], sumS[:]...)
	round.data.R = round.temp.r.Bytes()
	round.data.S = s.Bytes()
	if round.temp.fullBytesLen == 0 {
		round.data.M = round.temp.m.Bytes()
	} else {
		var mBytes = make([]byte, round.temp.fullBytesLen)
		round.temp.m.FillBytes(mBytes)
		round.data.M = mBytes
	}

	pk := edwards.PublicKey{
		Curve: round.Params().EC(),
		X:     round.key.EDDSAPub.X(),
		Y:     round.key.EDDSAPub.Y(),
	}

	ok := edwards.Verify(&pk, round.data.M, round.temp.r, s)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}
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
