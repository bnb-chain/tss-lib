// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"errors"
	"math/big"
	"time"
)

type (
	Parameters struct {
		ec                  elliptic.Curve
		partyID             *PartyID
		parties             *PeerContext
		partyCount          int
		threshold           int
		safePrimeGenTimeout time.Duration
		// deterministicU is the u which each TSS party use as input of key generation
		deterministicU *big.Int
	}

	ReSharingParameters struct {
		*Parameters
		newParties    *PeerContext
		newPartyCount int
		newThreshold  int
	}
)

const (
	defaultSafePrimeGenTimeout = 5 * time.Minute
)

// Exported, used in `tss` client
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int, optionalSafePrimeGenTimeout ...time.Duration) *Parameters {
	var safePrimeGenTimeout time.Duration
	if 0 < len(optionalSafePrimeGenTimeout) {
		if 1 < len(optionalSafePrimeGenTimeout) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalSafePrimeGenTimeout`"))
		}
		safePrimeGenTimeout = optionalSafePrimeGenTimeout[0]
	} else {
		safePrimeGenTimeout = defaultSafePrimeGenTimeout
	}
	return &Parameters{
		ec:                  ec,
		parties:             ctx,
		partyID:             partyID,
		partyCount:          partyCount,
		threshold:           threshold,
		safePrimeGenTimeout: safePrimeGenTimeout,
	}
}

// SetDeterministicU sets the deterministicU for Party
func (params *Parameters) SetDeterministicU(u *big.Int) {
	if u.BitLen() > 252 || u.BitLen() < 250 {
		return
	}
	params.deterministicU = u
}

// ClearDeterministicU clear the deterministicU and sets it to 0
func (params *Parameters) ClearDeterministicU() {
	params.deterministicU = big.NewInt(0)
}

// DeterministicU returns the deterministicU
func (params *Parameters) DeterministicU() *big.Int {
	return params.deterministicU
}

func (params *Parameters) EC() elliptic.Curve {
	return params.ec
}

func (params *Parameters) Parties() *PeerContext {
	return params.parties
}

func (params *Parameters) PartyID() *PartyID {
	return params.partyID
}

func (params *Parameters) PartyCount() int {
	return params.partyCount
}

func (params *Parameters) Threshold() int {
	return params.threshold
}

func (params *Parameters) SafePrimeGenTimeout() time.Duration {
	return params.safePrimeGenTimeout
}

// ----- //

// Exported, used in `tss` client
func NewReSharingParameters(ec elliptic.Curve, ctx, newCtx *PeerContext, partyID *PartyID, partyCount, threshold, newPartyCount, newThreshold int) *ReSharingParameters {
	params := NewParameters(ec, ctx, partyID, partyCount, threshold)
	return &ReSharingParameters{
		Parameters:    params,
		newParties:    newCtx,
		newPartyCount: newPartyCount,
		newThreshold:  newThreshold,
	}
}

func (rgParams *ReSharingParameters) OldParties() *PeerContext {
	return rgParams.Parties() // wr use the original method for old parties
}

func (rgParams *ReSharingParameters) OldPartyCount() int {
	return rgParams.partyCount
}

func (rgParams *ReSharingParameters) NewParties() *PeerContext {
	return rgParams.newParties
}

func (rgParams *ReSharingParameters) NewPartyCount() int {
	return rgParams.newPartyCount
}

func (rgParams *ReSharingParameters) NewThreshold() int {
	return rgParams.newThreshold
}

func (rgParams *ReSharingParameters) OldAndNewParties() []*PartyID {
	return append(rgParams.OldParties().IDs(), rgParams.NewParties().IDs()...)
}

func (rgParams *ReSharingParameters) OldAndNewPartyCount() int {
	return rgParams.OldPartyCount() + rgParams.NewPartyCount()
}

func (rgParams *ReSharingParameters) IsOldCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.parties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}

func (rgParams *ReSharingParameters) IsNewCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.newParties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}
