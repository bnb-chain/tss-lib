package keygen

import (
	"crypto/rsa"
	"fmt"
	"math/big"

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

var _ partyState = (*LocalParty)(nil)
var _ partyStateMonitor = (*LocalParty)(nil)
var _ partyStateMessageSender = (*LocalParty)(nil)

type (
	LocalPartySaveData struct {
		// public key (sum of ui * G for all P)
		PkX *big.Int
		PkY *big.Int

		// h1, h2 for range proofs (GG18 Fig. 13)
		H1 *big.Int
		H2 *big.Int

		// secret fields (not shared)
		Ui          *big.Int
		DeCommitUiG cmt.HashDeCommitment
		UiPolyGs    *vss.PolyGs
		PaillierSk  *paillier.PrivateKey
		PaillierPk  *paillier.PublicKey
		RSAKey      *rsa.PrivateKey
	}

	LocalParty struct {
		partyState
		data LocalPartySaveData

		// messaging
		out chan<- types.Message
		end chan<- LocalPartySaveData
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	p2pCtx *types.PeerContext,
	kgParams KGParameters,
	partyID *types.PartyID,
	out chan<- types.Message,
	end chan<- LocalPartySaveData) *LocalParty {
	p := &LocalParty{
		out:  out,
		end:  end,
		data: LocalPartySaveData{},
	}
	ps, err := NewRound1State(p2pCtx, kgParams, partyID, true, p)
	if err != nil {
		panic(err)
	}
	p.partyState = ps
	return p
}

// Implements Stringer
func (lp *LocalParty) String() string {
	return fmt.Sprintf("%s", lp.partyState.String())
}

func (lp *LocalParty) StartKeygenRound1() error {
	return lp.partyState.start()
}

func (lp *LocalParty) finishAndSaveKeygen() error {
	common.Logger.Infof("party %s: finished keygen. sending local data.", lp.getPartyID())

	// generate h1, h2 for range proofs (GG18 Fig. 13)
	lp.data.H1, lp.data.H2 = generateH1H2ForRangeProofs()

	// output local save data (inc. secrets)
	if lp.end != nil {
		lp.end <- lp.data
	} else {
		common.Logger.Warningf("party %s: end chan is nil, you missed this event", lp)
	}

	return nil
}

func (lp *LocalParty) setState(state partyState) {
	common.Logger.Infof("party %s: switched to round: %s", lp.getPartyID(), state.String())
	lp.partyState = state
}

func (lp *LocalParty) notifyKeygenRound1Complete() {
	lp.setState(NewRound2State(lp.partyState.(*round1)))

	if err := lp.partyState.start(); err != nil {
		panic(lp.wrapError(err, 2))
	}
}

func (lp *LocalParty) notifyKeygenRound2Complete() {
	lp.setState(NewRound3State(lp.partyState.(*round2)))

	if err := lp.partyState.start(); err != nil {
		panic(lp.wrapError(err, 3))
	}
}

func (lp *LocalParty) notifyKeygenRound3Complete() {
	if err := lp.finishAndSaveKeygen(); err != nil {
		panic(lp.wrapError(err, 4))
	}
}

func (lp *LocalParty) sendMsg(msg types.Message) {
	if lp.out == nil {
		panic(fmt.Errorf("party %s tried to send a message but out was nil", lp.getPartyID()))
	} else {
		lp.out <- msg
	}
}

func (lp *LocalParty) updateAndSendMsg(msg types.Message) {
	if _, err := lp.Update(msg); err != nil {
		panic(lp.wrapError(err, -1))
	}
	lp.sendMsg(msg)
}
