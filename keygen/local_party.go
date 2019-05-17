package keygen

import (
	"math/big"
	"tss-lib/common/math"
	cmt "tss-lib/crypto/commitments"
	"tss-lib/crypto/paillier"
)

var _ PartyStateMonitor = &LocalParty{}

type (
	LocalParty struct {
		*PartyState

		// messaging
		outChan     chan<- KGMessage

		// secret fields
		paillierSk *paillier.PrivateKey
	}
)

const (
	PaillierKeyLength = 1024
)

func NewLocalParty(kgParams KGParameters, partyID *PartyID, outChan chan<- KGMessage) *LocalParty {
	p := &LocalParty{
		outChan: outChan,
	}
	ps := NewPartyState(kgParams, partyID, p)
	p.PartyState = ps
	return p
}

func (p *LocalParty) GenerateAndStart() (bool, error) {
	// 1. calculate "partial" public key, make commitment -> (C, D)
	u1 := math.GetRandomPositiveInt(EC.N)

	uiGx, uiGy := EC.ScalarBaseMult(u1.Bytes())
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
	phase1Msg := NewKGPhase1CommitMessage(p.partyID, commitU1G.C, uiPaillierPk)

	// for this party, save the generated paillier sk
	p.paillierSk = uiPaillierSk

	p.Update(phase1Msg)

	p.sendToPeers(phase1Msg)

	return true, nil
}

func (p *LocalParty) NotifyPhase1Complete() {
	ids := make([]*big.Int, 0, p.kgParams.PartyCount)
}

func (p *LocalParty) NotifyPhase2Complete() {
	panic("implement me")
}

func (p *LocalParty) NotifyPhase3Complete() {
	panic("implement me")
}

func (p *LocalParty) sendToPeers(msg KGMessage) {
	if p.outChan != nil {
		p.outChan <- msg
	}
}
