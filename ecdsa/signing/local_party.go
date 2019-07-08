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

		temp LocalPartyTempData
		keys keygen.LocalPartySaveData
		data LocalPartySignData

		// messaging
		end chan<- LocalPartySignData
	}

	LocalPartySignData struct {
		Transaction []byte
		Signature   []byte
	}

	LocalPartyMessageStore struct {
		// messages
		signRound1CommitMessages      []*SignRound1CommitMessage
		signRound1MtAInitMessages     []*SignRound1MtAInitMessage // messages others sent to me
		signRound1SentMtaInitMessages []*SignRound1MtAInitMessage // messages I sent to others, for range_proof
		signRound2MtAMidMessages      []*SignRound2MtAMidMessage
		signRound3Messages            []*SignRound3Message
		signRound4DecommitMessage     []*SignRound4DecommitMessage
		signRound5CommitMessage       []*SignRound5CommitMessage
		signRound6DecommitMessage     []*SignRound6DecommitMessage
		signRound7CommitMessage       []*SignRound7CommitMessage
		signRound8DecommitMessage     []*SignRound8DecommitMessage
		signRound9SignatureMessage    []*SignRound9SignatureMessage
	}

	LocalPartyTempData struct {
		LocalPartyMessageStore

		// temp data (thrown away after sign)
		w     *big.Int
		bigWs []*crypto.ECPoint
		m,
		k,
		gamma *big.Int
		point    *crypto.ECPoint
		deCommit cmt.HashDeCommitment
		thelta,
		thelta_inverse,
		sigma *big.Int

		// round 2
		betas, // return value of Bob_mid
		c1jis,
		c2jis,
		vs []*big.Int // return value of Bob_mid_wc
		pi1jis []*mta.ProofBob
		pi2jis []*mta.ProofBobWC

		// round 5
		li     *big.Int
		bigAi  *crypto.ECPoint
		bigVi  *crypto.ECPoint
		roi    *big.Int
		DPower cmt.HashDeCommitment // TODO: bad name :(
		si     *big.Int
		r      *big.Int
		bigR   *crypto.ECPoint

		// round 7
		Ui     *crypto.ECPoint
		Ti     *crypto.ECPoint
		DTelda cmt.HashDeCommitment // TODO: bad name :(

		// TODO: delete, for testing
		VVV *crypto.ECPoint
	}
)

func NewLocalParty(
	m *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- LocalPartySignData,
) *LocalParty {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: &tss.BaseParty{
			Parameters: params,
			Out:        out,
		},
		temp: LocalPartyTempData{},
		data: LocalPartySignData{},
		end:  end,
	}
	// msgs init
	p.temp.signRound1MtAInitMessages = make([]*SignRound1MtAInitMessage, partyCount)
	p.temp.signRound1SentMtaInitMessages = make([]*SignRound1MtAInitMessage, partyCount)
	p.temp.signRound1CommitMessages = make([]*SignRound1CommitMessage, partyCount)
	p.temp.signRound2MtAMidMessages = make([]*SignRound2MtAMidMessage, partyCount)
	p.temp.signRound3Messages = make([]*SignRound3Message, partyCount)
	p.temp.signRound4DecommitMessage = make([]*SignRound4DecommitMessage, partyCount)
	p.temp.signRound5CommitMessage = make([]*SignRound5CommitMessage, partyCount)
	p.temp.signRound6DecommitMessage = make([]*SignRound6DecommitMessage, partyCount)
	p.temp.signRound7CommitMessage = make([]*SignRound7CommitMessage, partyCount)
	p.temp.signRound8DecommitMessage = make([]*SignRound8DecommitMessage, partyCount)
	p.temp.signRound9SignatureMessage = make([]*SignRound9SignatureMessage, partyCount)
	// TODO: later on, the message bytes should be passed in rather than hashed to big.Int
	p.temp.m = m
	p.temp.bigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.betas = make([]*big.Int, partyCount)
	p.temp.c1jis = make([]*big.Int, partyCount)
	p.temp.c2jis = make([]*big.Int, partyCount)
	p.temp.pi1jis = make([]*mta.ProofBob, partyCount)
	p.temp.pi2jis = make([]*mta.ProofBobWC, partyCount)
	p.temp.vs = make([]*big.Int, partyCount)

	// TODO data init

	round := newRound1(params, &key, &p.data, &p.temp, out)
	p.Round = round
	return p
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.PartyID(), p.Round.RoundNumber())
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.Parameters.PartyID()
}

func (p *LocalParty) Start() *tss.Error {
	p.Lock()
	defer p.Unlock()
	if round, ok := p.Round.(*round1); !ok || round == nil {
		return p.WrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	} else {
		common.Logger.Infof("party %s: signing round preparing", p.Round.Params().PartyID())
		round.prepare()
	}

	common.Logger.Infof("party %s: signing round %d starting", p.Round.Params().PartyID(), 1)
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
	case SignRound5CommitMessage:
		p.temp.signRound5CommitMessage[fromPIdx] = &m
	case SignRound6DecommitMessage:
		p.temp.signRound6DecommitMessage[fromPIdx] = &m
	case SignRound7CommitMessage:
		p.temp.signRound7CommitMessage[fromPIdx] = &m
	case SignRound8DecommitMessage:
		p.temp.signRound8DecommitMessage[fromPIdx] = &m
	case SignRound9SignatureMessage:
		p.temp.signRound9SignatureMessage[fromPIdx] = &m
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) Finish() {
	p.end <- p.data
}
