// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

const (
	TaskName = "eddsa-signing"
)

type (
	base struct {
		*tss.Parameters
		key     *keygen.LocalPartySaveData
		data    *common.SignatureData
		temp    *localTempData
		out     chan<- tss.Message
		end     chan<- *common.SignatureData
		ok      []bool // `ok` tracks parties which have been verified by Update()
		started bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	finalization struct {
		*round3
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*finalization)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.Parameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	Ps := round.Parties().IDs()
	ids := make([]*tss.PartyID, 0, len(round.ok))
	for j, ok := range round.ok {
		if ok {
			continue
		}
		ids = append(ids, Ps[j])
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

// get ssid from local params
//
// The message being signed is part of the pre-image, for the same reason as
// on the ECDSA side: it is the only per-execution value the protocol has of
// its own, so binding it keeps two runs of one committee over different
// messages apart even when the caller reuses a session nonce.
func (round *base) getSSID() ([]byte, error) {
	if round.temp.m == nil {
		return nil, round.WrapError(errors.New("message to sign is not set"), round.PartyID())
	}
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)                                                         // parties
	BigXjList, err := crypto.FlattenECPoints(round.key.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...)                    // BigXj
	ssidList = append(ssidList, big.NewInt(int64(round.number))) // round number
	ssidList = append(ssidList, round.temp.ssidNonce)            // caller-supplied session nonce
	ssidList = append(ssidList, round.temp.m)                    // message being signed
	// fullBytesLen decides what is actually signed: with it set, the message is
	// written as a fixed-length string (FillBytes, leading zeros preserved);
	// without it, as m.Bytes(). SHA512_256i hashes magnitudes only, so `m` alone
	// cannot separate those two -- two executions differing ONLY in
	// fullBytesLen used to share an SSID while binding different byte strings,
	// which made every proof under that SSID transferable between them. It is
	// also a per-party argument that no message carries and nothing compares, so
	// binding it here is what makes a disagreement observable at all.
	ssidList = append(ssidList, big.NewInt(int64(round.temp.fullBytesLen))) // message encoding width
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}
