package keygen

import (
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/schnorrZK"
	"github.com/binance-chain/tss-lib/types"
)

var _ partyState = (*round3)(nil)

func NewRound3State(r2 *round2) partyState {
	return &round3{
		r2,
		make([]*KGRound3ZKUProofMessage, r2.kgParams.partyCount),
	}
}

func (p *round3) start() error {
	Ps := p.p2pCtx.Parties()

	// for all Ps, calculate the public key
	uiGs := p.uiGs                     // de-committed in `tryNotifyRound2Complete`
	pkX, pkY := uiGs[0][0], uiGs[0][1] // P1
	for i := range Ps {                // P2..Pn
		if i == 0 {
			continue
		}
		pkX, pkY = EC().Add(pkX, pkY, uiGs[i][0], uiGs[i][1])
	}
	p.savedData.PKX,
	p.savedData.PKY = pkX, pkY

	// for all Ps, calculate private key shares
	skUi := p.kgRound2VssMessages[0].PiShare.Share
	for i := range Ps { // P2..Pn
		if i == 0 {
			continue
		}
		share := p.kgRound2VssMessages[i].PiShare.Share
		skUi = new(big.Int).Add(skUi, share)
	}
	skUi = new(big.Int).Mod(skUi, EC().N)

	// PRINT private share
	common.Logger.Debugf("private share: %x", skUi)

	// BROADCAST zk proof of ui
	uiProof := schnorrZK.NewZKProof(p.savedData.Ui)
	p3msg := NewKGRound3ZKUProofMessage(p.partyID, uiProof)
	p.msgSender.updateAndSendMsg(p3msg)

	common.Logger.Infof("party %s: keygen round 3 started", p.partyID)

	return nil
}

func (p *round3) Update(msg types.Message) (bool, error) {
	ok, err := p.validateBasis(msg)
	if !ok || err != nil {
		return ok, err
	}

	fromPIdx := msg.GetFrom().Index

	defer func(fromPIdx int) {
		p.lastMessages[fromPIdx] = msg
	}(fromPIdx)

	common.Logger.Infof("party %s update for: %s", p.partyID, msg.String())
	switch msg.(type) {
	case KGRound3ZKUProofMessage:
		// TODO guard - verify lastMessage from Pi (security)
		p3msg := msg.(KGRound3ZKUProofMessage)
		p.kgRound3ZKUProofMessage[fromPIdx] = &p3msg
		return p.tryNotifyRound3Complete(p3msg)

	default: // unrecognised message!
		return false, fmt.Errorf("unrecognised message: %v", msg)
	}

	return true, nil
}

func (p *round3) tryNotifyRound3Complete(p3msg KGRound3ZKUProofMessage) (bool, error) {
	fromPIdx := p3msg.From.Index

	// guard - VERIFY zk proof of ui
	uiG := p.uiGs[fromPIdx]
	if ok := p3msg.ZKUProof.Verify(uiG); !ok {
		common.Logger.Debugf("party %s: waiting for more kgRound2DeCommitMessages", p.partyID)
		return false, p.wrapError(fmt.Errorf("zk verify ui failed (from party %s)", p3msg.From), 3)
	}

	// guard - COUNT the required number of messages
	if !p.hasRequiredMessages() {
		return false, nil
	}

	// continue - completion
	p.currentRound = -1
	if p.monitor != nil {
		p.monitor.notifyKeygenRound3Complete()
	}
	return true, nil
}

func (p *round3) hasRequiredMessages() bool {
	for i := 0; i < p.kgParams.partyCount; i++ {
		if i != p.partyID.Index && p.kgRound3ZKUProofMessage[i] == nil {
			common.Logger.Debugf("party %s: waiting for more kgRound3ZKUProofMessage", p.partyID)
			return false
		}
	}
	return true
}
