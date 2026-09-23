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
	"github.com/bnb-chain/tss-lib/v4/crypto/mta"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

var zero = big.NewInt(0)

// nonPositiveNonceErrText is worded identically at every round-1 site that
// reads Parameters.SessionNonce().
const nonPositiveNonceErrText = "session nonce must be positive; call " +
	"Parameters.SetSessionNonce with a positive value agreed by all parties " +
	"before starting the round"

// round 1 represents round 1 of the signing part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- *common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	// Spec requires calculate H(M) here,
	// but considered different blockchain use different hash function we accept the converted big.Int
	// if this big.Int is not belongs to Zq, the client might not comply with common rule (for ECDSA):
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L263
	//
	// Both ends of the interval are checked here. Values at the bottom of the
	// range change the shape of the share computed in round 5 and are not
	// rejected anywhere downstream, so the membership test has to be complete
	// at this point.
	//
	// This is a Zq-membership test because m is a scalar on this curve: round 5
	// computes m*k and m*k + rx*sigma, round 7 computes -m mod N. The EdDSA
	// side deliberately has no counterpart -- there m only feeds a hash -- so
	// this guard must not be propagated there. See eddsa/signing/round_1.go.
	if round.temp.m.Sign() <= 0 || round.temp.m.Cmp(round.Params().EC().Params().N) >= 0 {
		return round.WrapError(errors.New("hashed message is not valid"))
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
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}
	round.temp.ssid = ssid

	k := common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)
	gamma := common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)

	pointGamma := crypto.ScalarBaseMult(round.Params().EC(), gamma)
	cmt := commitments.NewHashCommitment(round.Rand(), pointGamma.X(), pointGamma.Y())
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.pointGamma = pointGamma
	round.temp.deCommit = cmt.D

	i := round.PartyID().Index
	round.ok[i] = true

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		// Use ssid + j (receiver's index) as Session context so that the verifier (party j)
		// can reconstruct the same challenge using their ContextI = ssid + j in round 2.
		ContextJ := append([]byte(nil), round.temp.ssid...)
		ContextJ = append(ContextJ, new(big.Int).SetUint64(uint64(j)).Bytes()...)
		cA, pi, err := mta.AliceInit(ContextJ, round.Params().EC(), round.key.PaillierPKs[i], k, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.Rand())
		if err != nil {
			// The ring passed above is Pj's keygen output and this party is
			// proving into it, so a ring-decided failure is Pj's doing. Every
			// other way AliceInit can fail is a function of this party's own
			// Paillier key or its own randomness: no culprit, as before.
			if errors.Is(err, mta.ErrCounterpartyRingUnusable) {
				return round.WrapError(fmt.Errorf("failed to init mta: %v", err), Pj)
			}
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}
		r1msg1 := NewSignRound1Message1(Pj, round.PartyID(), cA, pi)
		round.temp.cis[j] = cA
		round.out <- r1msg1
	}

	r1msg2 := NewSignRound1Message2(round.PartyID(), cmt.C)
	round.temp.signRound1Message2s[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg1 := range round.temp.signRound1Message1s {
		if round.ok[j] {
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) {
			return false, nil
		}
		msg2 := round.temp.signRound1Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message2); ok {
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
	bigXs := round.key.BigXj

	if round.temp.keyDerivationDelta != nil {
		// adding the key derivation delta to the xi's
		// Suppose x has shamir shares x_0,     x_1,     ..., x_n
		// So x + D has shamir shares  x_0 + D, x_1 + D, ..., x_n + D
		mod := common.ModInt(round.Params().EC().Params().N)
		xi = mod.Add(round.temp.keyDerivationDelta, xi)
		round.key.Xi = xi
	}

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, bigWs, err := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, bigXs)
	if err != nil {
		return err
	}

	round.temp.w = wi
	round.temp.bigWs = bigWs
	return nil
}
