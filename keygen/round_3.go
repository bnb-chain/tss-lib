package keygen

import (
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/schnorrZK"
	"github.com/binance-chain/tss-lib/types"
)

var _ partyState = (*round3)(nil)

func NewRound3State(base *partyStateBase) partyState {
	return &round3{
		base,
	}
}

func (round *round3) start() error {
	Ps := round.p2pCtx.Parties()

	// for all Ps, calculate the public key
	uiGs := round.uiGs                 // de-committed in `tryNotifyRound2Complete`
	pkX, pkY := uiGs[0][0], uiGs[0][1] // P1
	for i := range Ps {                // P2..Pn
		if i == 0 {
			continue
		}
		pkX, pkY = EC().Add(pkX, pkY, uiGs[i][0], uiGs[i][1])
	}
	round.savedData.PKX,
		round.savedData.PKY = pkX, pkY

	// for all Ps, calculate private key shares
	skUi := round.kgRound2VssMessages[0].PiShare.Share
	for i := range Ps { // P2..Pn
		if i == 0 {
			continue
		}
		share := round.kgRound2VssMessages[i].PiShare.Share
		skUi = new(big.Int).Add(skUi, share)
	}
	skUi = new(big.Int).Mod(skUi, EC().N)

	// PRINT private share
	common.Logger.Debugf("private share: %x", skUi)

	// BROADCAST zk proof of ui
	uiProof := schnorrZK.NewZKProof(round.savedData.Ui)
	p3msg := NewKGRound3ZKUProofMessage(round.partyID, uiProof)
	round.msgSender.updateAndSendMsg(p3msg)

	common.Logger.Infof("party %s: keygen round 3 started", round.partyID)

	return nil
}

func (round *round3) Update(msg types.Message) (bool, error) {
	ok, err := round.validateBasis(msg)
	if !ok || err != nil {
		return ok, err
	}

	fromPIdx := msg.GetFrom().Index

	defer func(fromPIdx int) {
		round.lastMessages[fromPIdx] = msg
	}(fromPIdx)

	common.Logger.Infof("party %s update for: %s", round.partyID, msg.String())
	switch msg.(type) {
	case KGRound3ZKUProofMessage:
		// TODO guard - verify lastMessage from Pi (security)
		p3msg := msg.(KGRound3ZKUProofMessage)
		round.kgRound3ZKUProofMessage[fromPIdx] = &p3msg
		return round.tryNotifyRound3Complete(p3msg)

	default: // unrecognised message!
		return false, round.wrapError(fmt.Errorf("unrecognised message: %v", msg), 3)
	}

	return true, nil
}

func (round *round3) tryNotifyRound3Complete(p3msg KGRound3ZKUProofMessage) (bool, error) {
	fromPIdx := p3msg.From.Index

	// guard - VERIFY zk proof of ui
	uiG := round.uiGs[fromPIdx]
	if ok := p3msg.ZKUProof.Verify(uiG); !ok {
		common.Logger.Debugf("party %s: waiting for more kgRound2DeCommitMessages", round.partyID)
		return false, round.wrapError(fmt.Errorf("zk verify ui failed (from party %s)", p3msg.From), 3)
	}

	// guard - COUNT the required number of messages
	if !round.hasRequiredMessages() {
		return false, nil
	}

	// continue - completion
	round.currentRound = -1
	if round.monitor != nil {
		round.monitor.notifyKeygenRound3Complete()
	}
	return true, nil
}

func (round *round3) hasRequiredMessages() bool {
	for i := 0; i < round.kgParams.partyCount; i++ {
		if i != round.partyID.Index && round.kgRound3ZKUProofMessage[i] == nil {
			common.Logger.Debugf("party %s: waiting for more kgRound3ZKUProofMessage", round.partyID)
			return false
		}
	}
	return true
}
