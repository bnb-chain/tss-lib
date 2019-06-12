package keygen

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/types"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	PaillierModulusLen = 2048
	// RSA also 2048-bit modulus; two 1024-bit primes
	RSAModulusLen = 2048
)

type (
	LocalParty struct {
		*KGParameters
		round round

		mtx  *sync.Mutex
		data LocalPartySaveData
		temp LocalPartyTempData

		// messaging
		out chan<- types.Message
		end chan<- LocalPartySaveData
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int             // xi, kj
		PaillierSk  *paillier.PrivateKey // ski

		// public keys (Xj = uj*G for each Pj)
		BigXj       []*types.ECPoint      // Xj
		ECDSAPub    *types.ECPoint        // y
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
	params *KGParameters,
	out chan<- types.Message,
	end chan<- LocalPartySaveData,
) *LocalParty {
	partyCount := params.partyCount
	p := &LocalParty{
		KGParameters: params,
		mtx:          &sync.Mutex{},
		data:         LocalPartySaveData{},
		temp:         LocalPartyTempData{},
		out:          out,
		end:          end,
	}
	// data init
	p.data.BigXj = make([]*types.ECPoint, partyCount)
	p.data.PaillierPks = make([]*paillier.PublicKey, partyCount)
	p.data.NTildej = make([]*big.Int, partyCount)
	p.data.H1j, p.data.H2j = make([]*big.Int, partyCount), make([]*big.Int, partyCount)
	// msgs init
	p.temp.KGCs = make([]*cmt.HashCommitment, partyCount)
	p.temp.kgRound1CommitMessages = make([]*KGRound1CommitMessage, partyCount)
	p.temp.kgRound2VssMessages = make([]*KGRound2VssMessage, partyCount)
	p.temp.kgRound2DeCommitMessages = make([]*KGRound2DeCommitMessage, partyCount)
	p.temp.kgRound3PaillierProveMessage = make([]*KGRound3PaillierProveMessage, partyCount)
	//
	round := newRound1(params, &p.data, &p.temp, out)
	p.round = round
	return p
}

// Implements Stringer
func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.partyID.String(), p.round)
}

func (p *LocalParty) StartKeygenRound1() *keygenError {
	if _, ok := p.round.(*round1); !ok {
		return p.wrapError(errors.New("Could not start keygen. This party is in an unexpected round."), nil)
	}
	common.Logger.Infof("party %s: keygen round %d start()", p.round.params().partyID, 1)
	return p.round.start()
}

func (p *LocalParty) Update(msg types.Message) (ok bool, err *keygenError) {
	if _, err := p.validateMessage(msg); err != nil {
		return false, err
	}
	// need this mtx unlock hook, L137 is recursive so cannot use defer
	r := func(ok bool, err *keygenError) (bool, *keygenError) {
		p.mtx.Unlock()
		return ok, err
	}
	p.mtx.Lock() // data is written to P state below
	common.Logger.Debugf("party %s received message: %s", p.partyID, msg.String())
	if p.round != nil {
		common.Logger.Debugf("party %s round %d Update: %s", p.partyID, p.round.roundNumber(), msg.String())
	}
	if _, err := p.storeMessage(msg); err != nil {
		return r(false, err)
	}
	if p.round != nil {
		common.Logger.Debugf("party %s: keygen round %d update()", p.round.params().partyID, p.round.roundNumber())
		if _, err := p.round.update(); err != nil {
			return r(false, err)
		}
		if p.round.canProceed() {
			if p.round = p.round.nextRound(); p.round != nil {
				common.Logger.Infof("party %s: keygen round %d start()", p.round.params().partyID, p.round.roundNumber())
				if err := p.round.start(); err != nil {
					return r(false, err)
				}
			}
			p.mtx.Unlock()       // recursive so can't defer after return
			return p.Update(msg) // re-run round update or finish)
		}
		return r(true, nil)
	}
	// finished!
	common.Logger.Infof("party %s: finished!", p.partyID)
	p.end <- p.data
	return r(true, nil)
}

func (p *LocalParty) validateMessage(msg types.Message) (bool, *keygenError) {
	if msg.GetFrom() == nil {
		return false, p.wrapError(fmt.Errorf("update received nil msg: %s", msg), nil)
	}
	if msg == nil {
		return false, p.wrapError(fmt.Errorf("nil message received: %s", msg), msg.GetFrom())
	}
	if !msg.ValidateBasic() {
		return false, p.wrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) storeMessage(msg types.Message) (bool, *keygenError) {
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
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

	default: // unrecognised message!
		return false, p.wrapError(fmt.Errorf("unrecognised message: %v", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) finishAndSaveKeygen() error {
	common.Logger.Infof("party %s: finished keygen. sending local data.", p.partyID)

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

func (p *LocalParty) wrapError(err error, culprit *types.PartyID) *keygenError {
	return p.round.wrapError(err, culprit)
}
