package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/math"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/types"
)

var _ partyState = (*round1)(nil)

func NewRound1State(
	p2pCtx *types.PeerContext, kgParams KGParameters, partyID *types.PartyID, lp *LocalParty) (partyState, error) {

	partyCount := kgParams.partyCount

	base := partyStateBase{
		partyID: partyID,

		p2pCtx:    p2pCtx,
		kgParams:  kgParams,
		msgSender: lp,
		monitor:   lp,
		savedData: &lp.data,
		tempData:  &lp.temp,

		currentRound: 1,
		lastMessages: make([]types.Message, partyCount),
	}

	round1 := &round1{
		&base,
		make([]*KGRound1CommitMessage, partyCount),
	}

	return round1, nil
}

func (round *round1) start() error {
	// 1. calculate "partial" public key, make commitment -> (C, D)
	ui := math.GetRandomPositiveInt(EC().N)

	uiGx, uiGy := EC().ScalarBaseMult(ui.Bytes())

	// save uiGx, uiGy for this Pi for round 3
	round.savedData.BigXj = make([][]*big.Int, round.kgParams.partyCount)
	round.savedData.BigXj[round.partyID.Index] = []*big.Int{uiGx, uiGy}

	// prepare for concurrent Paillier, RSA key generation
	paiCh := make(chan paillier.Paillier)
	cmtCh := make(chan *cmt.HashCommitDecommit)
	rsaCh := make(chan *rsa.PrivateKey)

	// 2. generate Paillier public key "Ei", private key and proof
	go func(ch chan<- paillier.Paillier) {
		start := time.Now()
		PiPaillierSk, _ := paillier.GenerateKeyPair(PaillierModulusLen) // sk contains pk
		PiPaillierPf := PiPaillierSk.Proof()
		paillier := paillier.Paillier{PiPaillierSk, PiPaillierPf}
		common.Logger.Debugf("party %s: paillier keygen done. took %s\n", round, time.Since(start))
		ch <- paillier
	}(paiCh)

	// 4. generate auxilliary RSA primes for ZKPs later on
	go func(ch chan<- *rsa.PrivateKey) {
		start := time.Now()
		pk, err := rsa.GenerateMultiPrimeKey(rand.Reader, 2, RSAModulusLen)
		if err != nil {
			common.Logger.Errorf("RSA generation error: %s", err)
			ch <- nil
		}
		common.Logger.Debugf("party %s: rsa keygen done. took %s\n", round, time.Since(start))
		ch <- pk
	}(rsaCh)

	// 3. generate commitment of uiGx to reveal to other Pj later
	go func(ch chan<- *cmt.HashCommitDecommit) {
		start := time.Now()
		cmtDeCmtUiG, err := cmt.NewHashCommitment(uiGx, uiGy)
		if err != nil {
			common.Logger.Errorf("Commitment generation error: %s", err)
			ch <- nil
		}
		common.Logger.Debugf("party %s: commitment generated. took %s\n", round, time.Since(start))
		ch <- cmtDeCmtUiG
	}(cmtCh)

	pai := <-paiCh
	rsa := <-rsaCh
	if rsa == nil {
		return errors.New("RSA generation failed!")
	}
	cmt := <-cmtCh
	if cmt == nil {
		return errors.New("Commitment generation failed!")
	}

	// 5. collect and BROADCAST commitments, paillier pk + proof; round 1 message
	p1msg := NewKGRound1CommitMessage(round.partyID, cmt.C, &pai.PublicKey, pai.Proof, &rsa.PublicKey)

	// for this P: SAVE generated secrets, commitments, paillier vars; for round 2
	round.tempData.Ui = ui
	round.tempData.DeCommitUiG = cmt.D
	round.savedData.PaillierSk = pai.PrivateKey
	round.savedData.PaillierPk = &pai.PublicKey
	round.savedData.RSAKey = rsa

	round.kgRound1CommitMessages[round.partyID.Index] = &p1msg
	round.msgSender.sendMsg(p1msg)

	common.Logger.Infof("party %s: keygen round 1 started", round.partyID)

	return nil
}

func (round *round1) Update(msg types.Message) (bool, error) {
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
	case KGRound1CommitMessage: // Round 1 broadcast messages
		// guard - ensure no last message from Pi
		if round.lastMessages[fromPIdx] != nil {
			return false, round.wrapError(errors.New("unexpected lastMessage"), 1)
		}
		p1msg := msg.(KGRound1CommitMessage)
		round.kgRound1CommitMessages[fromPIdx] = &p1msg

		// guard - VERIFY received paillier pk/proof for Pi
		if ok := p1msg.PaillierPf.Verify(&p1msg.PaillierPk); !ok {
			return false, round.wrapError(fmt.Errorf("verify paillier proof failed (from party %s)", p1msg.From), 1)
		}

		// guard - COUNT the required number of messages
		if !round.hasRequiredMessages() {
			return false, nil
		}

		// continue - round 2, vss generate
		round.currentRound++
		if round.monitor != nil {
			round.monitor.notifyKeygenRound1Complete()
		}
		return true, nil

	default: // unrecognised message!
		return false, fmt.Errorf("unrecognised message: %v", msg)
	}
}

func (round *round1) hasRequiredMessages() bool {
	for i := 0; i < round.kgParams.partyCount; i++ {
		if i != round.partyID.Index && round.kgRound1CommitMessages[i] == nil {
			common.Logger.Debugf("party %s: waiting for more kgRound1CommitMessages", round.partyID)
			return false
		}
	}
	return true
}
