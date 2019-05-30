package keygen

import (
	"fmt"
	"math/big"

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
	PaillierKeyLength = 2048
)

var _ types.Party = (*LocalParty)(nil)
var _ partyStateMonitor = (*LocalParty)(nil)

type (
	LocalPartySaveData struct {
		// secret fields (not shared)
		Ui          *big.Int
		DeCommitUiG cmt.HashDeCommitment
		UiPolyGs    *vss.PolyGs
		PaillierSk  *paillier.PrivateKey
		PaillierPk  *paillier.PublicKey
	}

	LocalParty struct {
		*PartyState
		data LocalPartySaveData

		// messaging
		out        chan<- types.Message
		end        chan<- LocalPartySaveData
	}
)

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
	ps := NewPartyState(p2pCtx, kgParams, partyID, true, p)
	p.PartyState = ps
	return p
}

func (lp *LocalParty) StartKeygenRound1() error {
	// 1. calculate "partial" public key, make commitment -> (C, D)
	ui := math.GetRandomPositiveInt(EC.N)

	uiGx, uiGy := EC.ScalarBaseMult(ui.Bytes())

	// save uiGx, uiGy for this Pi for round 3
	lp.uiGs[lp.partyID.Index] = []*big.Int{uiGx, uiGy}

	cmtDeCmtUiG, err := cmt.NewHashCommitment(uiGx, uiGy)
	if err != nil {
		return err
	}

	// 2. generate Paillier public key "Ei", proof and private key
	PiPaillierPk, PiPaillierSk := paillier.GenerateKeyPair(PaillierKeyLength)
	PiPaillierPf := PiPaillierSk.Proof()

	// 3. BROADCAST key share, (commitments, paillier pks)

	// round 1 message
	p1msg := NewKGRound1CommitMessage(lp.partyID, cmtDeCmtUiG.C, PiPaillierPk, PiPaillierPf)

	// for this P: SAVE generated secrets, commitments, paillier vars; for round 2
	lp.data.Ui = ui
	lp.data.PaillierSk = PiPaillierSk
	lp.data.PaillierPk = PiPaillierPk
	lp.data.DeCommitUiG = cmtDeCmtUiG.D

	lp.Update(p1msg)
	lp.sendToPeers(p1msg)

	common.Logger.Infof("party %s: keygen round 1 complete", lp.partyID)

	return nil
}

func (lp *LocalParty) String() string {
	return fmt.Sprintf("%s", lp.PartyState.String())
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
		lp.sendToPeers(p2msg1)
	}

	// BROADCAST de-commitments and Shamir poly * Gs
	p2msg2 := NewKGRound2DeCommitMessage(lp.partyID, vsp, polyGs, lp.data.DeCommitUiG)
	lp.sendToPeers(p2msg2)

	common.Logger.Infof("party %s: keygen round 2 complete", lp.partyID)

	return nil
}

func (lp *LocalParty) startKeygenRound3() error {
	uiGs := lp.uiGs  // verified and de-committed in `tryNotifyRound2Complete`
	Ps := lp.p2pCtx.Parties()

	// for all Ps, calculate the public key
	pkX, pkY := uiGs[0][0], uiGs[0][1] // P1
	for i := range Ps { // P2..Pn
		if i == 0 {
			continue
		}
		pkX, pkY = EC.Add(pkX, pkY, uiGs[i][0], uiGs[i][1])
	}

	// PRINT public key
	fmt.Printf("public X: %x", pkX)
	fmt.Printf("public Y: %x", pkY)

	// for all Ps, calculate private key shares
	skUi := lp.kgRound2VssMessages[0].PiShare.Share
	for i := range Ps { // P2..Pn
		if i == 0 {
			continue
		}
		share := lp.kgRound2VssMessages[i].PiShare.Share
		skUi = new(big.Int).Add(skUi, share)
	}
	skUi = new(big.Int).Mod(skUi, EC.N)

	// PRINT private share
	common.Logger.Debugf("private share: %x", skUi)

	// BROADCAST zk proof of ui
	uiProof := schnorrZK.NewZKProof(lp.data.Ui)
	p3msg := NewKGRound3ZKUProofMessage(lp.partyID, uiProof)
	lp.sendToPeers(p3msg)

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

func (lp *LocalParty) sendToPeers(msg types.Message) {
	if lp.out == nil {
		panic(fmt.Errorf("party %s tried to send a message but out was nil", lp.partyID))
	} else {
		lp.out <- msg
	}
}
