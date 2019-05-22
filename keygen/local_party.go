package keygen

import (
	"math/big"

	"tss-lib/common/math"
	cmt "tss-lib/crypto/commitments"
	"tss-lib/crypto/paillier"
	"tss-lib/types"
)

var _ PartyStateMonitor = &LocalParty{}

type (
	LocalParty struct {
		*PartyState

		// messaging
		outChan     chan<- KGMessage

		// secret fields (not shared)
		ui         *big.Int
		paillierSk *paillier.PrivateKey
	}
)

const (
	PaillierKeyLength = 1024
)

func NewLocalParty(
		p2pCtx *types.PeerContext, kgParams KGParameters, partyID types.PartyID, outChan chan<- KGMessage) *LocalParty {
	p := &LocalParty{
		outChan: outChan,
	}
	ps := NewPartyState(p2pCtx, kgParams, partyID, p)
	p.PartyState = ps
	return p
}

func (lp *LocalParty) GenerateAndStart() (bool, error) {
	// 1. calculate "partial" public key, make commitment -> (C, D)
	ui := math.GetRandomPositiveInt(EC.N)

	uiGx, uiGy := EC.ScalarBaseMult(ui.Bytes())
	commitU1G, err := cmt.NewHashCommitment(uiGx, uiGy)
	if err != nil {
		return false, err
	}

	// 2. generate Paillier public key "Ei" and private key
	uiPaillierPk, uiPaillierSk := paillier.GenerateKeyPair(PaillierKeyLength)

	// 3. broadcast key share
	// commitU1G.C, commitU2G.C, commitU3G.C, commitU4G.C, commitU5G.C
	// u1PaillierPk, u2PaillierPk, u3PaillierPk, u4PaillierPk, u5PaillierPk

	// phase 1 message
	phase1Msg := NewKGPhase1CommitMessage(nil, &lp.partyID, commitU1G.C, uiPaillierPk)

	// for this party, save the generated secrets
	lp.ui = ui
	lp.paillierSk = uiPaillierSk

	lp.Update(phase1Msg)
	lp.sendToPeers(phase1Msg)

	return true, nil
}

func (lp *LocalParty) NotifyPhase1Complete() {
	// next step: compute the vss shares
	//ids := lp.p2pCtx.Parties().Keys()
	//_, polyG, _, shares, err := vss.Create(lp.kgParams.Threshold(), lp.kgParams.PartyCount(), ids, lp.ui)
	//if err != nil {
	//	panic(lp.wrapError(err, 1))
	//}
}

func (lp *LocalParty) NotifyPhase2Complete() {
	panic("implement me")
}

func (lp *LocalParty) NotifyPhase3Complete() {
	panic("implement me")
}

func (lp *LocalParty) sendToPeers(msg KGMessage) {
	if lp.outChan != nil {
		lp.outChan <- msg
	}
}
