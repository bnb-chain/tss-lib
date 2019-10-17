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
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
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

		temp LocalTempData
		data LocalSignData

		// outbound messaging
		end chan<- LocalSignData
	}

	LocalMessageStore struct {
		signRound1Message1s,
		signRound1Message2s,
		signRound2Messages,
		signRound3Messages,
		signRound4Messages,
		signRound5Messages,
		signRound6Messages,
		signRound7Messages,
		signRound8Messages,
		signRound9Messages []tss.ParsedMessage
	}

	LocalTempData struct {
		LocalMessageStore

		// temp data (thrown away after sign) / round 1
		w,
		m,
		k,
		theta,
		thetaInverse,
		sigma,
		gamma *big.Int
		cis        []*big.Int
		bigWs      []*crypto.ECPoint
		pointGamma *crypto.ECPoint
		deCommit   cmt.HashDeCommitment

		// round 2
		betas, // return value of Bob_mid
		c1jis,
		c2jis,
		vs []*big.Int // return value of Bob_mid_wc
		pi1jis []*mta.ProofBob
		pi2jis []*mta.ProofBobWC

		// round 5
		li,
		si,
		rx,
		ry,
		roi *big.Int
		bigR,
		bigAi,
		bigVi *crypto.ECPoint
		DPower cmt.HashDeCommitment

		// round 7
		Ui,
		Ti *crypto.ECPoint
		DTelda cmt.HashDeCommitment
	}

	LocalSignData struct {
		Transaction       []byte
		Signature         []byte
		SignatureRecovery byte
		R, S              *big.Int
	}
)

func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	keys keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- LocalSignData,
) *LocalParty {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: &tss.BaseParty{
			Out: out,
		},
		params: params,
		temp:   LocalTempData{},
		data:   LocalSignData{},
		end:    end,
	}
	// msgs init
	p.temp.signRound1Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound1Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound4Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound5Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound6Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound7Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound8Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound9Messages = make([]tss.ParsedMessage, partyCount)
	// data init
	p.temp.m = msg
	p.temp.cis = make([]*big.Int, partyCount)
	p.temp.bigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.betas = make([]*big.Int, partyCount)
	p.temp.c1jis = make([]*big.Int, partyCount)
	p.temp.c2jis = make([]*big.Int, partyCount)
	p.temp.pi1jis = make([]*mta.ProofBob, partyCount)
	p.temp.pi2jis = make([]*mta.ProofBobWC, partyCount)
	p.temp.vs = make([]*big.Int, partyCount)
	// round init
	round := newRound1(params, &keys, &p.data, &p.temp, out)
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
	} else {
		common.Logger.Infof("party %s: %s round preparing", p.Round.Params().PartyID(), TaskName)
		round.prepare()
	}

	common.Logger.Infof("party %s: %s round %d starting", p.Round.Params().PartyID(), TaskName, 1)
	return p.Round.Start()
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, "signing")
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
	case *SignRound1Message1:
		p.temp.signRound1Message1s[fromPIdx] = msg

	case *SignRound1Message2:
		p.temp.signRound1Message2s[fromPIdx] = msg

	case *SignRound2Message:
		p.temp.signRound2Messages[fromPIdx] = msg

	case *SignRound3Message:
		p.temp.signRound3Messages[fromPIdx] = msg

	case *SignRound4Message:
		p.temp.signRound4Messages[fromPIdx] = msg

	case *SignRound5Message:
		p.temp.signRound5Messages[fromPIdx] = msg

	case *SignRound6Message:
		p.temp.signRound6Messages[fromPIdx] = msg

	case *SignRound7Message:
		p.temp.signRound7Messages[fromPIdx] = msg

	case *SignRound8Message:
		p.temp.signRound8Messages[fromPIdx] = msg

	case *SignRound9Message:
		p.temp.signRound9Messages[fromPIdx] = msg

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) Finish() {
	p.end <- p.data
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.PartyID(), p.Round.RoundNumber())
}
