// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
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
		data LocalPartySaveData

		// outbound messaging
		end chan<- LocalPartySaveData
	}

	LocalMessageStore struct {
		kgRound1Messages,
		kgRound2Message1s,
		kgRound2Message2s,
		kgRound3Messages []tss.ParsedMessage
	}

	LocalTempData struct {
		LocalMessageStore

		// temp data (thrown away after keygen)
		ui            *big.Int // used for tests
		KGCs          []cmt.HashCommitment
		vs            vss.Vs
		shares        vss.Shares
		deCommitPolyG cmt.HashDeCommitment
	}

	LocalPreParams struct {
		PaillierSK        *paillier.PrivateKey // ski
		NTildei, H1i, H2i *big.Int             // n-tilde, h1, h2
	}

	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalPreParams
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// n-tilde, h1, h2 for range proofs
		NTildej, H1j, H2j []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj       []*crypto.ECPoint     // Xj
		PaillierPKs []*paillier.PublicKey // pkj

		// used for test assertions (may be discarded)
		ECDSAPub *crypto.ECPoint // y
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- LocalPartySaveData,
) *LocalParty {
	partyCount := params.PartyCount()
	p := &LocalParty{
		BaseParty: &tss.BaseParty{
			Out: out,
		},
		params: params,
		temp:   LocalTempData{},
		data:   LocalPartySaveData{},
		end:    end,
	}
	// msgs init
	p.temp.KGCs = make([]cmt.HashCommitment, partyCount)
	p.temp.kgRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound3Messages = make([]tss.ParsedMessage, partyCount)
	// data init
	p.data.BigXj = make([]*crypto.ECPoint, partyCount)
	p.data.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	p.data.NTildej = make([]*big.Int, partyCount)
	p.data.H1j, p.data.H2j = make([]*big.Int, partyCount), make([]*big.Int, partyCount)
	// round init
	round := newRound1(params, &p.data, &p.temp, out)
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
	return p.Round.Start()
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, "keygen")
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

	case *KGRound1Message:
		p.temp.kgRound1Messages[fromPIdx] = msg

	case *KGRound2Message1:
		p.temp.kgRound2Message1s[fromPIdx] = msg

	case *KGRound2Message2:
		p.temp.kgRound2Message2s[fromPIdx] = msg

	case *KGRound3Message:
		p.temp.kgRound3Messages[fromPIdx] = msg

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) Finish() {
	p.end <- p.data
}

// recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.PartyID(), p.Round.RoundNumber())
}
