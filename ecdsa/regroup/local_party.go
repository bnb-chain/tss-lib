// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package regroup

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.ReGroupParameters

		temp LocalPartyTempData
		key  keygen.LocalPartySaveData // we save straight back into here

		// outbound messaging
		end chan<- keygen.LocalPartySaveData
	}

	LocalPartyMessageStore struct {
		dgRound1Messages,
		dgRound2Message1s,
		dgRound2Message2s,
		dgRound3Message1s,
		dgRound3Message2s []tss.ParsedMessage
	}

	LocalPartyTempData struct {
		LocalPartyMessageStore

		// temp data (thrown away after rounds)
		OldBigXj  []*crypto.ECPoint
		OldKs     []*big.Int
		NewVs     vss.Vs
		NewShares vss.Shares
		VD,
		XAndKD cmt.HashDeCommitment
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.ReGroupParameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- keygen.LocalPartySaveData,
) *LocalParty {
	p := &LocalParty{
		BaseParty: &tss.BaseParty{
			Out: out,
		},
		params: params,
		temp:   LocalPartyTempData{},
		key:    key,
		end:    end,
	}
	// msgs init
	p.temp.dgRound1Messages = make([]tss.ParsedMessage, params.Threshold()+1)    // from t+1 of Old Committee
	p.temp.dgRound2Message1s = make([]tss.ParsedMessage, params.NewPartyCount()) // from n of New Committee
	p.temp.dgRound2Message2s = make([]tss.ParsedMessage, params.NewPartyCount()) // "
	p.temp.dgRound3Message1s = make([]tss.ParsedMessage, params.Threshold()+1)   // from t+1 of Old Committee
	p.temp.dgRound3Message2s = make([]tss.ParsedMessage, params.Threshold()+1)   // "
	// round init
	round := newRound1(params, &p.key, &p.key, &p.temp, out)
	p.Round = round
	return p
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) Start() *tss.Error {
	p.Lock()
	defer p.Unlock()
	if round, ok := p.Round.(*round1); !ok || round == nil {
		return p.WrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	common.Logger.Infof("party %s: %s round %d starting", p.Round.Params().PartyID(), TaskName, 1)
	defer func() {
		common.Logger.Debugf("party %s: %s round %d finished", p.Round.Params().PartyID(), TaskName, 1)
	}()
	return p.Round.Start()
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, "regroup")
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, to []*tss.PartyID) (bool, *tss.Error) {
	msg, err := tss.ParseMessage(wireBytes, from, to)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *DGRound1Message:
		p.temp.dgRound1Messages[fromPIdx] = msg

	case *DGRound2Message1:
		p.temp.dgRound2Message1s[fromPIdx] = msg

	case *DGRound2Message2:
		p.temp.dgRound2Message2s[fromPIdx] = msg

	case *DGRound3Message1:
		p.temp.dgRound3Message1s[fromPIdx] = msg

	case *DGRound3Message2:
		p.temp.dgRound3Message2s[fromPIdx] = msg

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) Finish() {
	p.end <- p.key
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.PartyID(), p.Round.RoundNumber())
}
