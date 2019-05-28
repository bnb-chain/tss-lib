package keygen

import (
	"fmt"
	"math/big"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common/math"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/types"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	PaillierKeyLength = 2048
)

var _ types.Party = (*LocalParty)(nil)
var _ PartyStateMonitor = (*LocalParty)(nil)

type (
	LocalParty struct {
		*PartyState

		// messaging
		out        chan<- types.Message

		// secret fields (not shared)
		ui          *big.Int
		deCommitUiG cmt.HashDeCommitment
		uiPolyGs    *vss.PolyGs
		paillierSk  *paillier.PrivateKey
	}
)

func NewLocalParty(
		p2pCtx *types.PeerContext, kgParams KGParameters, partyID *types.PartyID, out chan<- types.Message) *LocalParty {
	p := &LocalParty{
		out: out,
	}
	ps := NewPartyState(p2pCtx, kgParams, partyID, true, p)
	p.PartyState = ps
	return p
}

func (lp *LocalParty) StartKeygenRound1() error {
	// 1. calculate "partial" public key, make commitment -> (C, D)
	ui := math.GetRandomPositiveInt(EC.N)

	uiGx, uiGy := EC.ScalarBaseMult(ui.Bytes())
	cmtDeCmtUiG, err := cmt.NewHashCommitment(uiGx, uiGy)
	if err != nil {
		return err
	}

	// 2. generate Paillier public key "Ei", proof and private key
	PiPaillierPk, PiPaillierSk := paillier.GenerateKeyPair(PaillierKeyLength)
	PiPaillierPf := PiPaillierSk.Proof()

	// 3. broadcast key share, (commitments, paillier pks)

	// round 1 message
	p1msg := NewKGRound1CommitMessage(lp.partyID, cmtDeCmtUiG.C, PiPaillierPk, PiPaillierPf)

	// for this party: store generated secrets, commitments, paillier vars; for round 2
	lp.ui = ui
	lp.paillierSk = PiPaillierSk
	lp.deCommitUiG = cmtDeCmtUiG.D

	lp.Update(p1msg)
	lp.sendToPeers(p1msg)

	fmt.Printf("party %s: keygen round 1 complete", lp.partyID)

	return nil
}

func (lp *LocalParty) startKeygenRound2() error {
	// next step: compute the vss shares
	ids := lp.p2pCtx.Parties().Keys()
	vsp, polyGs, shares, err := vss.Create(lp.kgParams.Threshold(), lp.kgParams.PartyCount(), ids, lp.ui)
	lp.uiPolyGs = polyGs
	if err != nil {
		panic(lp.wrapError(err, 1))
	}

	// p2p send share ij to Pj
	for i, Pi := range lp.p2pCtx.Parties() {
		// skip our Pi
		if i == lp.partyID.Index {
			continue
		}
		p2msg1 := NewKGRound2VssMessage(Pi, lp.partyID, shares[i])
		lp.sendToPeers(p2msg1)
	}

	// broadcast de-commitments and Shamir poly * Gs
	p2msg2 := NewKGRound2DeCommitMessage(lp.partyID, vsp, polyGs, lp.deCommitUiG)
	lp.sendToPeers(p2msg2)

	fmt.Printf("party %s: keygen round 2 complete", lp.partyID)

	return nil
}

func (lp *LocalParty) startKeygenRound3() error {
	return errors.New("implement me")

	fmt.Printf("party %s: keygen round 3 complete", lp.partyID)

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
	panic("keygen finished!")
}

func (lp *LocalParty) sendToPeers(msg types.Message) {
	if lp.out == nil {
		panic(fmt.Errorf("party %s tried to send a message but out was nil", lp.partyID))
	} else {
		lp.out <- msg
	}
}
