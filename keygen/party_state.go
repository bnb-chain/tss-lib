package keygen

import (
	"fmt"
	"math/big"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/types"
)

type (
	partyState interface {
		start() error                           // start sending round messages
		Update(msg types.Message) (bool, error) // will be called on receive messages
		hasRequiredMessages() bool              // check whether received all messages for this round

		String() string

		getCurrentRound() int
		getPartyID() *types.PartyID
		wrapError(err error, round int) error
	}

	partyStateBase struct {
		partyID *types.PartyID

		p2pCtx    *types.PeerContext
		kgParams  KGParameters
		msgSender partyStateMessageSender
		monitor   partyStateMonitor
		savedData *LocalPartySaveData

		currentRound int
		lastMessages []types.Message

		// keygen state
		uiGs [][]*big.Int
	}

	round1 struct {
		*partyStateBase
		kgRound1CommitMessages []*KGRound1CommitMessage
	}

	round2 struct {
		*round1
		kgRound2VssMessages      []*KGRound2VssMessage
		kgRound2DeCommitMessages []*KGRound2DeCommitMessage
	}

	round3 struct {
		*round2
		kgRound3ZKUProofMessage []*KGRound3ZKUProofMessage
	}

	partyStateMonitor interface {
		setState(partyState)
		notifyKeygenRound1Complete()
		notifyKeygenRound2Complete()
		notifyKeygenRound3Complete()
	}

	partyStateMessageSender interface {
		sendMsg(msg types.Message)
		updateAndSendMsg(msg types.Message)
	}
)

func (p *partyStateBase) String() string {
	return fmt.Sprintf("id: %s, round: %d", p.partyID.String(), p.currentRound)
}

func (p *partyStateBase) validateBasis(msg types.Message) (bool, error) {
	if msg.GetFrom() == nil {
		return false, p.wrapError(errors.New("Update received nil msg"), p.currentRound)
	}
	if msg == nil {
		return false, fmt.Errorf("nil message received by party %s", p.partyID)
	}

	common.Logger.Infof("party %s received message: %s", p.partyID, msg.String())
	return true, nil
}

func (p *partyStateBase) getCurrentRound() int {
	return p.currentRound
}

func (p *partyStateBase) getPartyID() *types.PartyID {
	return p.partyID
}

func (lp *partyStateBase) wrapError(err error, round int) error {
	return errors.Wrapf(err, "party %s, round %d", lp.getPartyID(), lp.getCurrentRound())
}
