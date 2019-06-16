package keygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

var _ tss.Party = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.Parameters
		round tss.Round

		mtx  sync.Mutex
		data LocalPartySaveData
		temp LocalPartyTempData

		// messaging
		out chan<- tss.Message
		end chan<- LocalPartySaveData
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int             // xi, kj
		PaillierSk  *paillier.PrivateKey // ski

		// public keys (Xj = uj*G for each Pj)
		BigXj       []*crypto.ECPoint     // Xj
		ECDSAPub    *crypto.ECPoint       // y
		PaillierPks []*paillier.PublicKey // pkj

		// h1, h2 for range proofs
		NTildej, H1j, H2j []*big.Int
	}

	LocalPartyMessageStore struct {
		// messages
		kgRound1CommitMessages       []*KGRound1CommitMessage
		kgRound2VssMessages          []*KGRound2VssMessage
		kgRound2DeCommitMessages     []*KGRound2DeCommitMessage
		kgRound3PaillierProveMessage []*KGRound3PaillierProveMessage
	}

	LocalPartyTempData struct {
		LocalPartyMessageStore

		// temp data (thrown away after keygen)
		ui            *big.Int // used for tests
		KGCs          []*cmt.HashCommitment
		polyGs        *vss.PolyGs
		shares        vss.Shares
		deCommitPolyG cmt.HashDeCommitment
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
		Parameters: params,
		data:       LocalPartySaveData{},
		temp:       LocalPartyTempData{},
		out:        out,
		end:        end,
	}
	// data init
	p.data.BigXj = make([]*crypto.ECPoint, partyCount)
	p.data.PaillierPks = make([]*paillier.PublicKey, partyCount)
	p.data.NTildej = make([]*big.Int, partyCount)
	p.data.H1j, p.data.H2j = make([]*big.Int, partyCount), make([]*big.Int, partyCount)
	// msgs init
	p.temp.KGCs = make([]*cmt.HashCommitment, partyCount)
	p.temp.kgRound1CommitMessages = make([]*KGRound1CommitMessage, partyCount)
	p.temp.kgRound2VssMessages = make([]*KGRound2VssMessage, partyCount)
	p.temp.kgRound2DeCommitMessages = make([]*KGRound2DeCommitMessage, partyCount)
	p.temp.kgRound3PaillierProveMessage = make([]*KGRound3PaillierProveMessage, partyCount)
	// round init
	round := newRound1(params, &p.data, &p.temp, out)
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
	if round, ok := p.round.(*round1); !ok || round == nil {
		return p.wrapError(errors.New("Could not start. This party is in an unexpected state. Use the constructor and Start()."))
	}
	common.Logger.Infof("party %s: keygen round %d starting", p.round.Params().PartyID(), 1)
	return p.round.Start()
}

// Implements Party
func (p *LocalParty) Update(msg tss.Message) (ok bool, err *tss.Error) {
	if _, err := p.validateMessage(msg); err != nil {
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
	if ok, err := p.storeMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.round != nil {
		common.Logger.Debugf("party %s: keygen round %d update", p.round.Params().PartyID(), p.round.RoundNumber())
		if _, err := p.round.Update(); err != nil {
			return r(false, err)
		}
		if p.round.CanProceed() {
			if p.round = p.round.NextRound(); p.round != nil {
				common.Logger.Infof("party %s: keygen round %d starting", p.round.Params().PartyID(), p.round.RoundNumber())
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
	common.Logger.Infof("party %s: keygen finished!", p.PartyID())
	p.end <- p.data
	return r(true, nil)
}

// Implements Party
func (p *LocalParty) WaitingFor() []*tss.PartyID {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return p.round.WaitingFor()
}

// Legacy keygen.LocalParty method, called by Start() on the Party interface
func (p *LocalParty) StartKeygenRound1() *tss.Error {
	return p.Start()
}

func (p *LocalParty) validateMessage(msg tss.Message) (bool, *tss.Error) {
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

func (p *LocalParty) storeMessage(msg tss.Message) (bool, *tss.Error) {
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.(type) {

	case KGRound1CommitMessage: // Round 1 broadcast messages
		r1msg := msg.(KGRound1CommitMessage)
		p.temp.kgRound1CommitMessages[fromPIdx] = &r1msg

	case KGRound2VssMessage: // Round 2 P2P messages
		r2msg1 := msg.(KGRound2VssMessage)
		p.temp.kgRound2VssMessages[fromPIdx] = &r2msg1 // just collect

	case KGRound2DeCommitMessage:
		r2msg2 := msg.(KGRound2DeCommitMessage)
		p.temp.kgRound2DeCommitMessages[fromPIdx] = &r2msg2

	case KGRound3PaillierProveMessage:
		r3msg := msg.(KGRound3PaillierProveMessage)
		p.temp.kgRound3PaillierProveMessage[fromPIdx] = &r3msg

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) finishAndSaveKeygen() error {
	common.Logger.Infof("party %s: finished keygen. sending local data.", p.PartyID())

	close(p.out)

	// output local save data (inc. secrets)
	if p.end != nil {
		p.end <- p.data
		close(p.end)
	} else {
		common.Logger.Warningf("party %s: end chan is nil, you missed this event", p)
	}

	return nil
}

func (p *LocalParty) wrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return p.round.WrapError(err, culprits...)
}
