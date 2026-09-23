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

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// nonPositiveNonceErrText is worded identically at every round-1 site that
// reads Parameters.SessionNonce().
const nonPositiveNonceErrText = "session nonce must be positive; call " +
	"Parameters.SetSessionNonce with a positive value agreed by all parties " +
	"before starting the round"

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- *common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	// The message is consumed in round 3, inside a goroutine, when it is
	// hashed together with R and the public key; it is also bound into the
	// SSID below. Until this check existed the only thing that touched the
	// message this early was the session-nonce fallback, so a caller that
	// passed none got two broadcast rounds in before the failure surfaced as
	// a panic in round 3. Reject here, before anything is sent.
	if round.temp.m == nil {
		return round.WrapError(errors.New("message to sign is nil"))
	}
	// A negative value cannot come from any byte-string encoding of a
	// message, and it would be indistinguishable from its absolute value both
	// in the round-3 hash and in the SSID, since both take Bytes().
	//
	// The asymmetry with ecdsa/signing/round_1.go is deliberate. That side
	// rejects m <= 0 and m >= N because there m IS a scalar: round 5 computes
	// m*k and m*k + rx*sigma, and round 7 computes -m mod N, so Zq membership
	// is an algebraic requirement and m == 0 changes the shape of the share.
	// Here m only ever reaches sha512, in round 3's h = H(R || A || M) and in
	// the SSID pre-image; it is never a scalar. Importing that guard would
	// reject honest input: any message longer than 32 bytes exceeds N once
	// read as a big.Int, and m == 0 is unambiguous whenever fullBytesLen is
	// set, since FillBytes preserves the leading zeros. Do not "complete" this
	// check by analogy with the ECDSA one.
	if round.temp.m.Sign() < 0 {
		return round.WrapError(errors.New("message to sign is negative"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	// GG20 session binding: the caller must supply a session nonce that is
	// unique to this execution and agreed by every party in it. Keygen and
	// resharing already require one; signing used to substitute the message
	// hash instead, which gives no separation at all between two runs over
	// the same message and cannot be checked for freshness. Fail here rather
	// than proceed with an SSID nobody chose.
	nonce := round.Params().SessionNonce()
	if nonce == nil {
		return round.WrapError(errors.New(
			"signing requires a session nonce; call Parameters.SetSessionNonce " +
				"with a value agreed by all parties before starting the round"))
	}
	// See ecdsa/keygen/round_1.go: the SSID hash takes Bytes(), the magnitude
	// only, so -n and +n collide and 0 is one constant for every session.
	if nonce.Sign() <= 0 {
		return round.WrapError(errors.New(nonPositiveNonceErrText))
	}
	round.temp.ssidNonce = new(big.Int).Set(nonce)
	var err error
	round.temp.ssid, err = round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}
	// 1. select ri
	ri := common.GetRandomPositiveInt(round.Rand(), round.Params().EC().Params().N)

	// 2. make commitment
	pointRi := crypto.ScalarBaseMult(round.Params().EC(), ri)
	cmt := commitments.NewHashCommitment(round.Rand(), pointRi.X(), pointRi.Y())

	// 3. store r1 message pieces
	round.temp.ri = ri
	round.temp.pointRi = pointRi
	round.temp.deCommit = cmt.D

	i := round.PartyID().Index
	round.ok[i] = true

	// 4. broadcast commitment
	r1msg2 := NewSignRound1Message(round.PartyID(), cmt.C)
	round.temp.signRound1Messages[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
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

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, err := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks)
	if err != nil {
		return err
	}

	round.temp.wi = wi
	return nil
}
