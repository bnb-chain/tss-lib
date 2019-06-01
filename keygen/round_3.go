package keygen

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/schnorrZK"
	"github.com/binance-chain/tss-lib/types"
)

func (round *round3) roundNumber() int {
	return 3
}

func (round *round3) start() error {
	if round.started {
		return round.wrapError(errors.New("round already started"))
	}
	round.started = true

	Ps := round.p2pCtx.Parties()

	// compute uiG for each Pj
	for j, Pj := range Ps {
		p1Cmt := round.temp.kgRound1CommitMessages[j].Commitment
		p2msg2 := round.temp.kgRound2DeCommitMessages[j]
		cmtDeCmt := commitments.HashCommitDecommit{C: p1Cmt, D: p2msg2.DeCommitment}
		ok, uiG, err := cmtDeCmt.DeCommit()
		if err != nil {
			return round.wrapError(err)
		}
		if !ok {
			return round.wrapError(fmt.Errorf("decommitment failed (from party %s)", Pj))
		}
		round.save.BigXj[j] = uiG
	}

	// for all Ps, compute the public key
	bigXj := round.save.BigXj            // de-committed above
	pkX, pkY := bigXj[0][0], bigXj[0][1] // P1
	for j := range Ps { // P2..Pn
		if j == 0 {
			continue
		}
		pkX, pkY = EC().Add(pkX, pkY, bigXj[j][0], bigXj[j][1])
	}
	round.save.PKX,
		round.save.PKY = pkX, pkY
	round.save.BigXj = bigXj

	// for all Ps, compute private key shares
	skUi := round.temp.kgRound2VssMessages[0].PiShare.Share
	for j := range Ps { // P2..Pn
		if j == 0 {
			continue
		}
		share := round.temp.kgRound2VssMessages[j].PiShare.Share
		skUi = new(big.Int).Add(skUi, share)
	}
	skUi = new(big.Int).Mod(skUi, EC().N)

	// PRINT private share
	common.Logger.Debugf("private share: %x", skUi)

	// BROADCAST zk proof of ui
	uiProof := schnorrZK.NewZKProof(round.temp.Ui)
	p3msg := NewKGRound3ZKUProofMessage(round.partyID, uiProof)
	round.temp.kgRound3ZKUProofMessage[round.partyID.Index] = &p3msg
	round.out <- p3msg
	return nil
}

func (round *round3) canAccept(msg types.Message) bool {
	if _, ok := msg.(KGRound3ZKUProofMessage); !ok {
		return false
	}
	return true
}

func (round *round3) update(msg types.Message) (bool, error) {
	if !round.canAccept(msg) { // double check
		return false, nil
	}

	fromPIdx := msg.GetFrom().Index
	p3msg := msg.(KGRound3ZKUProofMessage)

	// guard - VERIFY zk proof of ui
	uiG := round.save.BigXj[fromPIdx]
	if ok := p3msg.ZKUProof.Verify(uiG); !ok {
		common.Logger.Debugf("party %s: waiting for more kgRound2DeCommitMessages", round.partyID)
		return false, round.wrapError(fmt.Errorf("zk verify ui failed (from party %s)", p3msg.From))
	}
	return true, nil
}

func (round *round3) canProceed() bool {
	for i := 0; i < round.params().partyCount; i++ {
		if round.temp.kgRound3ZKUProofMessage[i] == nil {
			common.Logger.Debugf("party %s: waiting for more kgRound3ZKUProofMessage", round.partyID)
			return false
		}
	}
	return true
}

func (round *round3) nextRound() round {
	if !round.canProceed() {
		return round
	}
	return nil // finished!
}
