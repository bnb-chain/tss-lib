package keygen

import (
	"crypto/rsa"
	"fmt"
	"math/big"

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

		data  LocalPartySaveData
		temp  LocalPartyTempData
		round round

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
		Ui          *big.Int
		DeCommitUiG cmt.HashDeCommitment
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
		out:          out,
		end:          end,
		data:         LocalPartySaveData{},
		temp:         LocalPartyTempData{},
	}
	p.data.BigXj = make([][]*big.Int, partyCount)
	p.temp.kgRound1CommitMessages = make([]*KGRound1CommitMessage, partyCount)
	p.temp.kgRound2VssMessages = make([]*KGRound2VssMessage, partyCount)
	p.temp.kgRound2DeCommitMessages = make([]*KGRound2DeCommitMessage, partyCount)
	p.temp.kgRound3ZKUProofMessage = make([]*KGRound3ZKUProofMessage, partyCount)
	round := NewRound1State(params, &p.data, &p.temp, out)
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
	fromPIdx := msg.GetFrom().Index

	if _, err := p.validateMessage(msg); err != nil {
		return false, err
	}

	defer func(fromPIdx int) {
		common.Logger.Infof("party %s: keygen round %d update()", p.round.params().partyID, p.round.roundNumber())
		if p.round.canAccept(msg) {
			p.round.update(msg)
		}
		if p.round.canProceed() {
			p.round = p.round.nextRound()
			if p.round != nil {
				common.Logger.Infof("party %s: keygen round %d start()", p.round.params().partyID, p.round.roundNumber())
				p.round.start()
			} else {  // finished!
				p.end <- p.data
			}
		}
	}(fromPIdx)

	common.Logger.Infof("party %s update for: %s", p.partyID, msg.String())
	switch msg.(type) {

	case KGRound1CommitMessage: // Round 1 broadcast messages
		p1msg := msg.(KGRound1CommitMessage)
		p.temp.kgRound1CommitMessages[fromPIdx] = &p1msg
		return true, nil

	case KGRound2VssMessage: // Round 2 P2P messages
		p2msg1 := msg.(KGRound2VssMessage)
		p.temp.kgRound2VssMessages[fromPIdx] = &p2msg1 // just collect
		return true, nil

	case KGRound2DeCommitMessage:
		p2msg2 := msg.(KGRound2DeCommitMessage)
		p.temp.kgRound2DeCommitMessages[fromPIdx] = &p2msg2
		return true, nil

	case KGRound3ZKUProofMessage:
		p3msg := msg.(KGRound3ZKUProofMessage)
		p.temp.kgRound3ZKUProofMessage[fromPIdx] = &p3msg
		return true, nil

	default: // unrecognised message!
		return false, fmt.Errorf("unrecognised message: %v", msg)
	}
}

func (p *LocalParty) validateMessage(msg types.Message) (bool, error) {
	if msg.GetFrom() == nil {
		return false, p.wrapError(errors.New("Update received nil msg"), p.round.roundNumber())
	}
	if msg == nil {
		return false, fmt.Errorf("nil message received by party %s", p.partyID)
	}

	common.Logger.Infof("party %s received message: %s", p.partyID, msg.String())
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
