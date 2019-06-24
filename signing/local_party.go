package keygen

import (
	"errors"
	"fmt"
	"sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
)

var _ tss.Party = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.Parameters
		round tss.Round

		mtx  sync.Mutex
		temp LocalPartyTempData
		data LocalPartySignData

		// messaging
		out chan<- tss.Message
		end chan<- LocalPartySignData
	}

	LocalPartySignData struct {
		Transaction []byte
		Signature   []byte
	}

	LocalPartyMessageStore struct {
		// messages
	}

	LocalPartyTempData struct {
		// temp data
	}
)

func NewLocalParty(
	params *tss.Parameters,
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
	// TODO msgs init
	// TODO data init
	// TODO round init
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
	if round, ok := p.round.(*preparation); !ok || round == nil {
		return p.wrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
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
func (p *LocalParty) PartyID() *tss.PartyID {
	return p.Parameters.PartyID()
}

// Implements Party
func (p *LocalParty) WaitingFor() []*tss.PartyID {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return p.round.WaitingFor()
}

func (p *LocalParty) validateMessage(msg tss.Message) (bool, *tss.Error) {
	return false, nil
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
