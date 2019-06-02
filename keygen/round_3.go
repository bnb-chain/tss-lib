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
	round.resetOk()

	// compute uiG for each Pj
	Ps := round.p2pCtx.Parties()
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
	uiProof := schnorrZK.NewZKProof(round.temp.ui)
	p3msg := NewKGRound3ZKUProofMessage(round.partyID, uiProof)
	round.temp.kgRound3ZKUProofMessage[round.partyID.Index] = &p3msg
	round.out <- p3msg
	return nil
}

func (round *round3) canAccept(msg types.Message) bool {
	if msg, ok := msg.(*KGRound3ZKUProofMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round3) update() (bool, error) {
	// guard - VERIFY zk proof of ui
	for j, msg := range round.temp.kgRound3ZKUProofMessage {
		if round.ok[j] { continue }
		if !round.canAccept(msg) {
			return false, nil
		}
		uiG := round.save.BigXj[j]
		if len(uiG) != 2 {
			return false, nil
		}
		if ok := msg.ZKUProof.Verify(uiG); !ok {
			common.Logger.Debugf("party %s: waiting for more kgRound2DeCommitMessages", round.partyID)
			return false, round.wrapError(fmt.Errorf("zk verify ui failed (from party %s)", msg.From))
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) nextRound() round {
	return nil // finished!
}
