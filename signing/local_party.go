package signing

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

var _ tss.Party = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.Parameters
		round tss.Round

		mtx  sync.Mutex
		temp LocalPartyTempData
		keys keygen.LocalPartySaveData
		data LocalPartySignData

		// messaging
		out chan<- tss.Message
		end chan<- LocalPartySignData
	}

	LocalPartySignData struct {
		Transaction []byte
		Signature   []byte

		// TODO: this field is used for verifying first 5 rounds, will delete later on
		R *crypto.ECPoint
	}

	LocalPartyMessageStore struct {
		// messages
		signRound1CommitMessages  []*SignRound1CommitMessage
		signRound1MtAInitMessages []*SignRound1MtAInitMessage
		signRound2MtAMidMessages  []*SignRound2MtAMidMessage
		signRound3Messages        []*SignRound3Message
		signRound4DecommitMessage []*SignRound4DecommitMessage
	}

	LocalPartyTempData struct {
		LocalPartyMessageStore

		// temp data (thrown away after sign)
		w              *big.Int
		m              *big.Int
		k              *big.Int
		gamma          *big.Int
		point          *crypto.ECPoint
		deCommit       cmt.HashDeCommitment
		betas          []*big.Int // return value of Bob_mid
		thelta         *big.Int
		thelta_inverse *big.Int
	}
)

func (p *LocalParty) ValidateMessage(msg tss.Message) (bool, *tss.Error) {
	if msg == nil {
		return false, p.wrapError(fmt.Errorf("received nil msg: %s", msg))
	}
	if msg.GetFrom() == nil {
		return false, p.wrapError(fmt.Errorf("received msg with nil sender: %s", msg))
	}
	if !msg.ValidateBasic() {
		return false, p.wrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.Message) (bool, *tss.Error) {
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch m := msg.(type) {
	case SignRound1MtAInitMessage:
		p.temp.signRound1MtAInitMessages[fromPIdx] = &m
	case SignRound1CommitMessage:
		p.temp.signRound1CommitMessages[fromPIdx] = &m
	case SignRound2MtAMidMessage:
		p.temp.signRound2MtAMidMessages[fromPIdx] = &m
	case SignRound3Message:
		p.temp.signRound3Messages[fromPIdx] = &m
	case SignRound4DecommitMessage:
		p.temp.signRound4DecommitMessage[fromPIdx] = &m
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) Finish() {
	panic("implement me")
}

func (p *LocalParty) Rnd() tss.Round {
	panic("implement me")
}

func (p *LocalParty) Lock() {
	panic("implement me")
}

func (p *LocalParty) Unlock() {
	panic("implement me")
}

func NewLocalParty(
	m *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- LocalPartySignData,
) *LocalParty {
	partyCount := params.PartyCount()
	p := &LocalParty{
		Parameters: params,
		temp:       LocalPartyTempData{},
		data:       LocalPartySignData{},
		out:        out,
		end:        end,
	}
	// msgs init
	p.temp.signRound1MtAInitMessages = make([]*SignRound1MtAInitMessage, partyCount)
	p.temp.signRound1CommitMessages = make([]*SignRound1CommitMessage, partyCount)
	p.temp.signRound2MtAMidMessages = make([]*SignRound2MtAMidMessage, partyCount)
	p.temp.signRound3Messages = make([]*SignRound3Message, partyCount)
	p.temp.signRound4DecommitMessage = make([]*SignRound4DecommitMessage, partyCount)
	// TODO: later on, the message bytes should be passed in rather than hashed to big.Int
	p.temp.m = m
	p.temp.betas = make([]*big.Int, partyCount)

	// TODO data init

	// round init, TODO: change to start with preparation round
	round := newRound1(params, &key, &p.data, &p.temp, out)
	p.round = round
	return p
}

// Implements Stringer
func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.PartyID(), p.round)
}

// Implements Party
func (p *LocalParty) Start() *tss.Error {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	// TODO: make the start round be preparation
	if round, ok := p.round.(*round1); !ok || round == nil {
		return p.wrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	common.Logger.Infof("party %s: signing round %d starting", p.round.Params().PartyID(), 1)
	return p.round.Start()
}

// Implements Party
func (p *LocalParty) Update(msg tss.Message) (ok bool, err *tss.Error) {
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	// need this mtx unlock hook, L137 is recursive so cannot use defer
	r := func(ok bool, err *tss.Error) (bool, *tss.Error) {
		p.mtx.Unlock()
		return ok, err
	}
	p.mtx.Lock() // data is written to P state below
	common.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
	if p.round != nil {
		common.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.round.RoundNumber(), msg.String())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.round != nil {
		common.Logger.Debugf("party %s: sign round %d update", p.round.Params().PartyID(), p.round.RoundNumber())
		if _, err := p.round.Update(); err != nil {
			return r(false, err)
		}
		if p.round.CanProceed() {
			if p.round = p.round.NextRound(); p.round != nil {
				common.Logger.Infof("party %s: signing round %d starting", p.round.Params().PartyID(), p.round.RoundNumber())
				if err := p.round.Start(); err != nil {
					return r(false, err)
				}
			}
			p.mtx.Unlock()       // recursive so can't defer after return
			return p.Update(msg) // re-run round update or finish)
		}
		return r(true, nil)
	}
	// finished!
	common.Logger.Infof("party %s: signing finished!", p.PartyID())
	p.end <- p.data
	return r(true, nil)
}

// Implements Party
func (p *LocalParty) PartyID() *tss.PartyID {
	return p.Parameters.PartyID()
}

// Implements Party
func (p *LocalParty) WaitingFor() []*tss.PartyID {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return p.round.WaitingFor()
}

func (p *LocalParty) storeMessage(msg tss.Message) (bool, *tss.Error) {
	return false, nil
}

func (p *LocalParty) finish() {
	// TODO send sign data through channel here
}

func (p *LocalParty) rnd() tss.Round {
	return p.round
}

func (p *LocalParty) lock() {
	p.mtx.Lock()
}

func (p *LocalParty) unlock() {
	p.mtx.Unlock()
}

func (p *LocalParty) wrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return p.round.WrapError(err, culprits...)
}
