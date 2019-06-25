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
		Temp LocalPartyTempData
		Data LocalPartySaveData

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

		// original index (added for local testing)
		Index int
	}

	LocalPartyMessageStore struct {
		// messages
		kgRound1CommitMessages       []*KGRound1CommitMessage
		KgRound2VssMessages          []*KGRound2VssMessage
		kgRound2DeCommitMessages     []*KGRound2DeCommitMessage
		kgRound3PaillierProveMessage []*KGRound3PaillierProveMessage
	}

	LocalPartyTempData struct {
		LocalPartyMessageStore

		// temp data (thrown away after keygen)
		Ui            *big.Int // used for tests
		KGCs          []*cmt.HashCommitment
		PolyGs        *vss.PolyGs
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
		Temp:       LocalPartyTempData{},
		Data:       LocalPartySaveData{Index: params.PartyID().Index},
		out:        out,
		end:        end,
	}
	// msgs init
	p.Temp.KGCs = make([]*cmt.HashCommitment, partyCount)
	p.Temp.kgRound1CommitMessages = make([]*KGRound1CommitMessage, partyCount)
	p.Temp.KgRound2VssMessages = make([]*KGRound2VssMessage, partyCount)
	p.Temp.kgRound2DeCommitMessages = make([]*KGRound2DeCommitMessage, partyCount)
	p.Temp.kgRound3PaillierProveMessage = make([]*KGRound3PaillierProveMessage, partyCount)
	// data init
	p.Data.BigXj = make([]*crypto.ECPoint, partyCount)
	p.Data.PaillierPks = make([]*paillier.PublicKey, partyCount)
	p.Data.NTildej = make([]*big.Int, partyCount)
	p.Data.H1j, p.Data.H2j = make([]*big.Int, partyCount), make([]*big.Int, partyCount)
	// round init
	round := newRound1(params, &p.Data, &p.Temp, out)
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
		return p.wrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	common.Logger.Infof("party %s: keygen round %d starting", p.round.Params().PartyID(), 1)
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
	p.end <- p.Data
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

// Legacy keygen.LocalParty method, called by Start() on the Party interface
func (p *LocalParty) StartKeygenRound1() *tss.Error {
	return p.Start()
}

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
	switch msg.(type) {

	case KGRound1CommitMessage: // Round 1 broadcast messages
		r1msg := msg.(KGRound1CommitMessage)
		p.Temp.kgRound1CommitMessages[fromPIdx] = &r1msg

	case KGRound2VssMessage: // Round 2 P2P messages
		r2msg1 := msg.(KGRound2VssMessage)
		p.Temp.KgRound2VssMessages[fromPIdx] = &r2msg1 // just collect

	case KGRound2DeCommitMessage:
		r2msg2 := msg.(KGRound2DeCommitMessage)
		p.Temp.kgRound2DeCommitMessages[fromPIdx] = &r2msg2

	case KGRound3PaillierProveMessage:
		r3msg := msg.(KGRound3PaillierProveMessage)
		p.Temp.kgRound3PaillierProveMessage[fromPIdx] = &r3msg

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) Finish() {
	p.end <- p.Data
}

func (p *LocalParty) finishAndSaveKeygen() error {
	common.Logger.Infof("party %s: finished keygen. sending local data.", p.PartyID())

	close(p.out)

	// output local save data (inc. secrets)
	if p.end != nil {
		p.end <- p.Data
		close(p.end)
	} else {
		common.Logger.Warningf("party %s: end chan is nil, you missed this event", p)
	}

	return nil
}

func (p *LocalParty) Rnd() tss.Round {
	return p.round
}

func (p *LocalParty) Lock() {
	p.mtx.Lock()
}

func (p *LocalParty) Unlock() {
	p.mtx.Unlock()
}

func (p *LocalParty) wrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return p.round.WrapError(err, culprits...)
}
