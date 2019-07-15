package regroup

import (
	"errors"
	"fmt"

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

		temp LocalPartyTempData
		key  keygen.LocalPartySaveData
		data keygen.LocalPartySaveData

		// messaging
		end chan<- keygen.LocalPartySaveData
	}

	LocalPartyMessageStore struct {
		// messages
		dgRound1OldCommitteeCommitMessages []*DGRound1OldCommitteeCommitMessage
		dgRound2NewCommitteeACKMessage []*DGRound2NewCommitteeACKMessage
	}

	LocalPartyTempData struct {
		LocalPartyMessageStore

		// temp data (thrown away after rounds)
		Di        cmt.HashDeCommitment
		NewVs     vss.Vs
		NewShares vss.Shares
		BigXs     []*crypto.ECPoint
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
		temp: LocalPartyTempData{},
		data: keygen.LocalPartySaveData{Index: params.PartyID().Index},
		end:  end,
	}
	// msgs init
	p.temp.dgRound1OldCommitteeCommitMessages = make([]*DGRound1OldCommitteeCommitMessage, params.NewPartyCount())
	p.temp.dgRound2NewCommitteeACKMessage = make([]*DGRound2NewCommitteeACKMessage, params.PartyCount())
	// data init
	// round init
	round := newRound1(params, &p.key, &p.data, &p.temp, out)
	p.Round = round
	return p
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.PartyID(), p.Round.RoundNumber())
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.Round.Params().PartyID()
}

func (p *LocalParty) Start() *tss.Error {
	p.Lock()
	defer p.Unlock()
	if round, ok := p.Round.(*round1); !ok || round == nil {
		return p.WrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	common.Logger.Infof("party %s: keygen round %d starting", p.Round.Params().PartyID(), 1)
	return p.Round.Start()
}

func (p *LocalParty) Update(msg tss.Message, phase string) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, phase)
}

func (p *LocalParty) StoreMessage(msg tss.Message) (bool, *tss.Error) {
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.(type) {

	case DGRound1OldCommitteeCommitMessage: // Round 1 broadcast messages
		r1msg := msg.(DGRound1OldCommitteeCommitMessage)
		p.temp.dgRound1OldCommitteeCommitMessages[fromPIdx] = &r1msg

	case DGRound2NewCommitteeACKMessage:
		r2msg := msg.(DGRound2NewCommitteeACKMessage)
		p.temp.dgRound2NewCommitteeACKMessage[fromPIdx] = &r2msg

	// TODO implement other messages

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) Finish() {
	p.end <- p.data
}
