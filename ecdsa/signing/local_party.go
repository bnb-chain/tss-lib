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
	"github.com/binance-chain/tss-lib/crypto"
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
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data common.SignatureData

		// outbound messaging
		out chan<- tss.Message
		end chan<- common.SignatureData
	}

	localMessageStore struct {
		presignRound1Messages,
		presignRound2Messages,
		presignRound3Messages,
		signRound1Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		w                   *big.Int
		BigWs               []*crypto.ECPoint
		KShare              *big.Int
		
		BigGammaShare       *crypto.ECPoint
		K                   *big.Int
		G                   *big.Int
		KNonce              *big.Int
		GNonce              *big.Int
		keyDerivationDelta  *big.Int

		// round 2
		GammaShare          *big.Int
		DeltaShareBetas     []*big.Int
		ChiShareBetas       []*big.Int

		// round 3
		BigGamma            *crypto.ECPoint
		DeltaShareAlphas    []*big.Int
		ChiShareAlphas      []*big.Int
		DeltaShare          *big.Int
		ChiShare            *big.Int
		BigDeltaShare       *crypto.ECPoint

		// round 4
		m                   *big.Int
		BigR                *crypto.ECPoint
		Rx                  *big.Int
		SigmaShare          *big.Int
	}
)

func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- common.SignatureData,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      common.SignatureData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.presignRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound1Messages = make([]tss.ParsedMessage, partyCount)
	// temp data init
	p.temp.keyDerivationDelta = keyDerivationDelta
	p.temp.m = msg
	p.temp.BigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.DeltaShareBetas = make([]*big.Int, partyCount)
	p.temp.ChiShareBetas = make([]*big.Int, partyCount)
	p.temp.DeltaShareAlphas = make([]*big.Int, partyCount)
	p.temp.ChiShareAlphas = make([]*big.Int, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName, func(round tss.Round) *tss.Error {
		round1, ok := round.(*presign1)
		if !ok {
			return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
		}
		if err := round1.prepare(); err != nil {
			return round.WrapError(err)
		}
		return nil
	})
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *PreSignRound1Message:
		p.temp.presignRound1Messages[fromPIdx] = msg
	case *PreSignRound2Message:
		p.temp.presignRound2Messages[fromPIdx] = msg
	case *PreSignRound3Message:
		p.temp.presignRound3Messages[fromPIdx] = msg
	case *SignRound4Message:
		p.temp.signRound1Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
