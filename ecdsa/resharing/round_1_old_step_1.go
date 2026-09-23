// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.ReSharingParameters, input, save *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *keygen.LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, temp, input, save, out, end, make([]bool, len(params.OldParties().IDs())), make([]bool, len(params.NewParties().IDs())), false, 1},
	}
}

// dualRoleErrText is the fixed text of the round-1 dual-role rejection.
const dualRoleErrText = "this party is in both the old and the new committee; " +
	"the two committees must be disjoint (re-sharing in place is not a supported configuration)"

// nonPositiveNonceErrText is worded identically at every round-1 site that
// reads Parameters.SessionNonce().
const nonPositiveNonceErrText = "session nonce must be positive; call " +
	"Parameters.SetSessionNonce with a positive value agreed by all parties " +
	"before starting the round"

// rejectDualRole is defence in depth behind tss.NewReSharingParameters, which
// refuses a non-empty committee intersection at construction time. That check
// is construction-time ONLY: NewPeerContext holds the caller's slice by
// reference and PeerContext.SetIDs rewrites it, so a caller can still steer a
// party into both committees after its Parameters were built.
//
// It reports no culprits on purpose. This is a purely local configuration
// fault; blaming a peer would misattribute it to an honest old party, and the
// PartyIDs involved carry old-committee indices that mean nothing in the new
// committee's index space.
func (round *round1) rejectDualRole() *tss.Error {
	if round.ReSharingParams().IsOldCommittee() && round.ReSharingParams().IsNewCommittee() {
		return round.WrapError(errors.New(dualRoleErrText))
	}
	return nil
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	// Refuse before any state is touched: `started` stays false, so CanProceed()
	// can never be satisfied and the party cannot advance out of round 1.
	if err := round.rejectDualRole(); err != nil {
		return err
	}
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allNewOK()

	// EVERY party needs the session nonce, not just the old committee, and it is
	// required HERE so that a party which lacks it fails before it has exchanged
	// anything.
	//
	// The old committee needs it to derive the ssid. The new committee needs it
	// to CHECK what the old committee declares -- it cannot derive the ssid
	// itself, because getSSID's pre-image is the old committee's save data. That
	// check lives in round 2, but requiring the nonce there would mean a
	// misconfigured new party gets a full round of messages in before anything
	// tells it that it was never going to be able to compare. The requirement is
	// the same for both roles, so it is stated once, in one place, for both.
	if nonce := round.Params().SessionNonce(); nonce != nil {
		// See ecdsa/keygen/round_1.go: the SSID hash takes Bytes(), the
		// magnitude only, so -n and +n collide and 0 is one constant for
		// every session.
		if nonce.Sign() <= 0 {
			return round.WrapError(errors.New(nonPositiveNonceErrText))
		}
		round.temp.ssidNonce = new(big.Int).Set(nonce)
	} else {
		return round.WrapError(errors.New(
			"resharing requires a session nonce; call Parameters.SetSessionNonce " +
				"with a value agreed by all parties before starting the round"))
	}

	if !round.ReSharingParams().IsOldCommittee() {
		return nil
	}
	round.allOldOK()

	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}
	round.temp.ssid = ssid
	Pi := round.PartyID()
	i := Pi.Index

	// 1. PrepareForSigning() -> w_i
	xi, ks, bigXj := round.input.Xi, round.input.Ks, round.input.BigXj
	if round.Threshold()+1 > len(ks) {
		return round.WrapError(fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks)), round.PartyID())
	}
	newKs := round.NewParties().IDs().Keys()
	wi, _, err := signing.PrepareForSigning(round.Params().EC(), i, len(round.OldParties().IDs()), xi, ks, bigXj)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 2.
	vi, shares, err := vss.Create(round.Params().EC(), round.NewThreshold(), wi, newKs, round.Rand())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 3.
	flatVis, err := crypto.FlattenECPoints(vi)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	vCmt := commitments.NewHashCommitment(round.Rand(), flatVis...)

	// 4. populate temp data
	round.temp.VD = vCmt.D
	round.temp.NewShares = shares

	// 5. "broadcast" C_i to members of the NEW committee
	r1msg := NewDGRound1Message(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		round.input.ECDSAPub, vCmt.C, ssid,
		sessionNonceHash(round.temp.ssidNonce))
	round.temp.dgRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	// accept messages from old -> new committee
	if _, ok := msg.Content().(*DGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	// Re-check here, not only in Start(): the guard has to hold the party still
	// even if the dual role was introduced after Start() ran. Returning before
	// any `oldOK` bit is set is what keeps the party from advancing.
	if err := round.rejectDualRole(); err != nil {
		return false, err
	}
	// only the new committee receive in this round
	if !round.ReSharingParameters.IsNewCommittee() {
		return true, nil
	}
	// accept messages from old -> new committee
	ret := true
	for j, msg := range round.temp.dgRound1Messages {
		if round.oldOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.oldOK[j] = true

		// save the ecdsa pub received from the old committee (this old party j,
		// not slot 0). Reading the loop's current message is what makes the
		// anomaly check below actually compare each old party's advertised key
		// against the first one seen; reading dgRound1Messages[0] on every
		// iteration made the check a no-op and let a malicious old slot-0 party
		// swap the reshared public key (SRC-2026-1155). msg is already proven
		// non-nil by the CanAccept guard above.
		r1msg := msg.Content().(*DGRound1Message)
		candidate, err := r1msg.UnmarshalECDSAPub(round.Params().EC())
		if err != nil {
			return false, round.WrapError(errors.New("unable to unmarshal the ecdsa pub key"), msg.GetFrom())
		}
		if round.save.ECDSAPub != nil &&
			!candidate.Equals(round.save.ECDSAPub) {
			// uh oh - anomaly!
			return false, round.WrapError(errors.New("ecdsa pub key did not match what we received previously"), msg.GetFrom())
		}
		round.save.ECDSAPub = candidate
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
