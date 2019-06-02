package keygen

import (
	"crypto/rsa"
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

		mtx   *sync.Mutex
		data  LocalPartySaveData
		temp  LocalPartyTempData

		// messaging
		out chan<- types.Message
		end chan<- LocalPartySaveData
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int     // xi, kj
		BigXj       [][]*big.Int // Xj
		UiPolyGs    *vss.PolyGs
		PaillierSk  *paillier.PrivateKey // ski
		PaillierPk  *paillier.PublicKey  // pki
		RSAKey      *rsa.PrivateKey      // N(tilde)j

		// public key (sum of ui * G for all P)
		PKX, PKY *big.Int

		// h1, h2 for range proofs (GG18 Fig. 13)
		H1 *big.Int
		H2 *big.Int
	}

	LocalPartyMessageStore struct {
		// messages
		kgRound1CommitMessages   []*KGRound1CommitMessage
		kgRound2VssMessages      []*KGRound2VssMessage
		kgRound2DeCommitMessages []*KGRound2DeCommitMessage
		kgRound3ZKUProofMessage  []*KGRound3ZKUProofMessage
	}

	LocalPartyTempData struct {
		LocalPartyMessageStore

		// temp data (thrown away after keygen)
		ui          *big.Int
		deCommitUiG cmt.HashDeCommitment
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
	p.data.BigXj = make([][]*big.Int, partyCount)
	p.temp.kgRound1CommitMessages = make([]*KGRound1CommitMessage, partyCount)
	p.temp.kgRound2VssMessages = make([]*KGRound2VssMessage, partyCount)
	p.temp.kgRound2DeCommitMessages = make([]*KGRound2DeCommitMessage, partyCount)
	p.temp.kgRound3ZKUProofMessage = make([]*KGRound3ZKUProofMessage, partyCount)
	round := newRound1(params, &p.data, &p.temp, out)
	p.round = round
	return p
}

// Implements Stringer
func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.partyID.String(), p.round)
}

func (p *LocalParty) StartKeygenRound1() error {
	if _, ok := p.round.(*round1); !ok {
		return errors.New("Could not start keygen. This party is in an unexpected round.")
	}
	return p.round.start()
}

func (p *LocalParty) Update(msg types.Message) (bool, error) {
	p.mtx.Lock()
	// needed, L137 is recursive so cannot use defer
	r := func(a1 bool, a2 error) (bool, error) {
		p.mtx.Unlock()
		return a1, a2
	}
	if _, err := p.validateMessage(msg); err != nil {
		return r(false, err)
	}
	if p.round != nil {
		common.Logger.Infof("party %s round %d Update: %s", p.partyID, p.round.roundNumber(), msg.String())
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
				p.round.start()
			}
			p.mtx.Unlock() // recursive so can't defer after return
			return p.Update(msg) // re-run round update or finish)
		}
		return r(true, nil)
	}
	// finished!
	common.Logger.Infof("party %s: finished!", p.partyID)
	p.end <- p.data
	return r(true, nil)
}

func (p *LocalParty) validateMessage(msg types.Message) (bool, error) {
	if msg.GetFrom() == nil {
		return false, p.wrapError(errors.New("update received nil msg"), p.round.roundNumber())
	}
	if msg == nil {
		return false, fmt.Errorf("nil message received by party %s", p.partyID)
	}

	common.Logger.Debugf("party %s received message: %s", p.partyID, msg.String())
	return true, nil
}

func (p *LocalParty) storeMessage(msg types.Message) (bool, error) {
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store messages beyond current round
	switch msg.(type) {

	case KGRound1CommitMessage: // Round 1 broadcast messages
		p1msg := msg.(KGRound1CommitMessage)
		p.temp.kgRound1CommitMessages[fromPIdx] = &p1msg

	case KGRound2VssMessage: // Round 2 P2P messages
		p2msg1 := msg.(KGRound2VssMessage)
		p.temp.kgRound2VssMessages[fromPIdx] = &p2msg1 // just collect

	case KGRound2DeCommitMessage:
		p2msg2 := msg.(KGRound2DeCommitMessage)
		p.temp.kgRound2DeCommitMessages[fromPIdx] = &p2msg2

	case KGRound3ZKUProofMessage:
		p3msg := msg.(KGRound3ZKUProofMessage)
		p.temp.kgRound3ZKUProofMessage[fromPIdx] = &p3msg

	default: // unrecognised message!
		return false, fmt.Errorf("unrecognised message: %v", msg)
	}
	return true, nil
}

func (p *LocalParty) finishAndSaveKeygen() error {
	common.Logger.Infof("party %s: finished keygen. sending local data.", p.partyID)

	// generate h1, h2 for range proofs (GG18 Fig. 13)
	p.data.H1, p.data.H2 = generateH1H2ForRangeProofs()

	// output local save data (inc. secrets)
	if p.end != nil {
		p.end <- p.data
	} else {
		common.Logger.Warningf("party %s: end chan is nil, you missed this event", p)
	}

	return nil
}

func (p *LocalParty) wrapError(err error, round int) error {
	return errors.Wrapf(err, "party %s, round %d", p.partyID, round)
}
