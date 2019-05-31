package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/math"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/schnorrZK"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/types"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	PaillierModulusLen = 2048
	// RSA also 2048-bit modulus; two 1024-bit primes
	RSAModulusLen = 2048
)

var _ types.Party = (*LocalParty)(nil)
var _ partyStateMonitor = (*LocalParty)(nil)

type (
	LocalPartySaveData struct {
		// public key (sum of ui * G for all P)
		PkX         *big.Int
		PkY         *big.Int

		// secret fields (not shared)
		Ui          *big.Int
		DeCommitUiG cmt.HashDeCommitment
		UiPolyGs    *vss.PolyGs
		PaillierSk  *paillier.PrivateKey
		PaillierPk  *paillier.PublicKey
		RSAKey      *rsa.PrivateKey
	}

	LocalParty struct {
		*partyState
		data LocalPartySaveData

		// messaging
		out        chan<- types.Message
		end        chan<- LocalPartySaveData
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
		out: out,
		end: end,
		data: LocalPartySaveData{},
	}
	ps := newPartyState(p2pCtx, kgParams, partyID, true, p)
	p.partyState = ps
	return p
}

// Implements Stringer
func (lp *LocalParty) String() string {
	return fmt.Sprintf("%s", lp.partyState.String())
}

func (lp *LocalParty) StartKeygenRound1() error {
	// 1. calculate "partial" public key, make commitment -> (C, D)
	ui := math.GetRandomPositiveInt(EC().N)

	uiGx, uiGy := EC().ScalarBaseMult(ui.Bytes())

	// save uiGx, uiGy for this Pi for round 3
	lp.uiGs[lp.partyID.Index] = []*big.Int{uiGx, uiGy}

	// prepare for concurrent key generation
	paiCh := make(chan paillier.Paillier)
	cmtCh := make(chan *cmt.HashCommitDecommit)
	rsaCh := make(chan *rsa.PrivateKey)

	// 2. generate Paillier public key "Ei", private key and proof
	go func(ch chan<- paillier.Paillier) {
		PiPaillierSk, _ := paillier.GenerateKeyPair(PaillierModulusLen) // sk contains pk
		PiPaillierPf := PiPaillierSk.Proof()
		paillier := paillier.Paillier{PiPaillierSk, PiPaillierPf}
		ch <- paillier
	}(paiCh)

	// 3. generate commitment of uiGx to reveal to other Pj later
	go func(ch chan<- *cmt.HashCommitDecommit) {
		cmtDeCmtUiG, err := cmt.NewHashCommitment(uiGx, uiGy)
		if err != nil {
			common.Logger.Errorf("Commitment generation error: %s", err)
			ch <- nil
		}
		ch <- cmtDeCmtUiG
	}(cmtCh)

	// 4. generate auxilliary RSA primes for ZKPs later on
	go func(ch chan<- *rsa.PrivateKey) {
		pk, err := rsa.GenerateMultiPrimeKey(rand.Reader, 2, RSAModulusLen)
		if err != nil {
			common.Logger.Errorf("RSA generation error: %s", err)
			ch <- nil
		}
		ch <- pk
	}(rsaCh)

	pai := <-paiCh
	cmt := <-cmtCh
	if cmt == nil {
		return errors.New("Commitment generation failed!")
	}
	rsa := <-rsaCh
	if rsa == nil {
		return errors.New("RSA generation failed!")
	}

	// 5. collect and BROADCAST commitments, paillier pk + proof; round 1 message
	p1msg := NewKGRound1CommitMessage(lp.partyID, cmt.C, &pai.PublicKey, pai.Proof, &rsa.PublicKey)

	// for this P: SAVE generated secrets, commitments, paillier vars; for round 2
	lp.data.Ui = ui
	lp.data.PaillierSk = pai.PrivateKey
	lp.data.PaillierPk = &pai.PublicKey
	lp.data.DeCommitUiG = cmt.D
	lp.data.RSAKey = rsa

	lp.kgRound1CommitMessages[lp.partyID.Index] = &p1msg
	lp.sendMsg(p1msg)

	common.Logger.Infof("party %s: keygen round 1 complete", lp.partyID)

	return nil
}

func (lp *LocalParty) startKeygenRound2() error {
	// next step: compute the vss shares
	ids := lp.p2pCtx.Parties().Keys()
	vsp, polyGs, shares, err := vss.Create(lp.kgParams.Threshold(), lp.data.Ui, ids)
	if err != nil {
		panic(lp.wrapError(err, 1))
	}

	// for this P: SAVE UiPolyGs
	lp.data.UiPolyGs = polyGs

	// p2p send share ij to Pj
	for i, Pi := range lp.p2pCtx.Parties() {
		p2msg1 := NewKGRound2VssMessage(Pi, lp.partyID, shares[i])
		// do not send to this Pi, but store for round 3
		if i == lp.partyID.Index {
			lp.kgRound2VssMessages[i] = &p2msg1
			continue
		}
		lp.updateAndSendMsg(p2msg1)
	}

	// BROADCAST de-commitments and Shamir poly * Gs
	p2msg2 := NewKGRound2DeCommitMessage(lp.partyID, vsp, polyGs, lp.data.DeCommitUiG)
	lp.updateAndSendMsg(p2msg2)

	common.Logger.Infof("party %s: keygen round 2 complete", lp.partyID)

	return nil
}

func (lp *LocalParty) startKeygenRound3() error {
	Ps := lp.p2pCtx.Parties()

	// for all Ps, calculate the public key
	uiGs := lp.uiGs  // de-committed in `tryNotifyRound2Complete`
	pkX, pkY := uiGs[0][0], uiGs[0][1] // P1
	for i := range Ps { // P2..Pn
		if i == 0 {
			continue
		}
		pkX, pkY = EC().Add(pkX, pkY, uiGs[i][0], uiGs[i][1])
	}
	lp.data.PkX, lp.data.PkY = pkX, pkY

	// for all Ps, calculate private key shares
	skUi := lp.kgRound2VssMessages[0].PiShare.Share
	for i := range Ps { // P2..Pn
		if i == 0 {
			continue
		}
		share := lp.kgRound2VssMessages[i].PiShare.Share
		skUi = new(big.Int).Add(skUi, share)
	}
	skUi = new(big.Int).Mod(skUi, EC().N)

	// PRINT private share
	common.Logger.Debugf("private share: %x", skUi)

	// BROADCAST zk proof of ui
	uiProof := schnorrZK.NewZKProof(lp.data.Ui)
	p3msg := NewKGRound3ZKUProofMessage(lp.partyID, uiProof)
	lp.updateAndSendMsg(p3msg)

	return nil
}

func (lp *LocalParty) finishAndSaveKeygen() error {
	common.Logger.Infof("party %s: finished keygen. sending local data.", lp.partyID)

	// output local save data (inc. secrets)
	lp.end <- lp.data

	return nil
}

func (lp *LocalParty) notifyKeygenRound1Complete() {
	if err := lp.startKeygenRound2(); err != nil {
		panic(lp.wrapError(err, 2))
	}
}

func (lp *LocalParty) notifyKeygenRound2Complete() {
	if err := lp.startKeygenRound3(); err != nil {
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
		panic(fmt.Errorf("party %s tried to send a message but out was nil", lp.partyID))
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
