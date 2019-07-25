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

		// messaging
		end chan<- keygen.LocalPartySaveData
	}

	LocalPartyMessageStore struct {
		// messages
		dgRound1OldCommitteeCommitMessages []*DGRound1OldCommitteeCommitMessage
		dgRound2NewCommitteeACKMessage     []*DGRound2NewCommitteeACKMessage
		dgRound2PaillierPublicKeyMessage   []*DGRound2NewCommitteePaillierPublicKeyMessage
		dgRound3ShareMessage               []*DGRound3OldCommitteeShareMessage
		dgRound3DeCommitMessage            []*DGRound3OldCommitteeDeCommitMessage
	}

	LocalPartyTempData struct {
		LocalPartyMessageStore

		// temp data (thrown away after rounds)
		OldBigXj  []*crypto.ECPoint
		OldKs     []*big.Int
		NewVs     vss.Vs
		NewShares vss.Shares
		VD,
		XAndKD    cmt.HashDeCommitment
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
	p.temp.dgRound1OldCommitteeCommitMessages = make([]*DGRound1OldCommitteeCommitMessage, params.Threshold() + 1)
	p.temp.dgRound2NewCommitteeACKMessage = make([]*DGRound2NewCommitteeACKMessage, params.NewPartyCount())
	p.temp.dgRound2PaillierPublicKeyMessage = make([]*DGRound2NewCommitteePaillierPublicKeyMessage, params.NewPartyCount())
	p.temp.dgRound3ShareMessage = make([]*DGRound3OldCommitteeShareMessage, params.Threshold() + 1)
	p.temp.dgRound3DeCommitMessage = make([]*DGRound3OldCommitteeDeCommitMessage, params.Threshold() + 1)
	// round init
	round := newRound1(params, &p.key, &p.key, &p.temp, out)
	p.Round = round
	return p
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.PartyID(), p.Round.RoundNumber())
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

func (p *LocalParty) Update(msg tss.Message, phase string) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, phase)
}

func (p *LocalParty) StoreMessage(msg tss.Message) (bool, *tss.Error) {
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch m := msg.(type) {
	case DGRound1OldCommitteeCommitMessage: // Round 1 broadcast messages
		p.temp.dgRound1OldCommitteeCommitMessages[fromPIdx] = &m

	case DGRound2NewCommitteeACKMessage:
		p.temp.dgRound2NewCommitteeACKMessage[fromPIdx] = &m

	case DGRound2NewCommitteePaillierPublicKeyMessage:
		p.temp.dgRound2PaillierPublicKeyMessage[fromPIdx] = &m

	case DGRound3OldCommitteeShareMessage:
		p.temp.dgRound3ShareMessage[fromPIdx] = &m

	case DGRound3OldCommitteeDeCommitMessage:
		p.temp.dgRound3DeCommitMessage[fromPIdx] = &m

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) Finish() {
	p.end <- p.key
}
