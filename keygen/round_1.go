package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/math"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/types"
)

func NewRound1State(params *KGParameters, save *LocalPartySaveData, temp *LocalPartyTempData, out chan<- types.Message) round {
	return &round1{params, save, temp, out, &sync.RWMutex{}, make([]bool, params.partyCount), false}
}

func (round *round1) roundNumber() int {
	return 1
}

func (round *round1) start() error {
	if round.started {
		return round.wrapError(errors.New("round already started"))
	}
	round.started = true
	round.resetOk()

	// calculate "partial" public key, make commitment -> (C, D)
	ui := math.GetRandomPositiveInt(EC().N)

	uiGx, uiGy := EC().ScalarBaseMult(ui.Bytes())

	// save uiGx, uiGy for this Pi for round 3
	round.save.BigXj = make([][]*big.Int, round.partyCount)
	round.save.BigXj[round.partyID.Index] = []*big.Int{uiGx, uiGy}

	// prepare for concurrent Paillier, RSA key generation
	paiCh := make(chan paillier.Paillier)
	rsaCh := make(chan *rsa.PrivateKey)

	// generate Paillier public key "Ei", private key and proof
	go func(ch chan<- paillier.Paillier) {
		start := time.Now()
		PiPaillierSk, _ := paillier.GenerateKeyPair(PaillierModulusLen) // sk contains pk
		PiPaillierPf := PiPaillierSk.Proof()
		paillier := paillier.Paillier{PiPaillierSk, PiPaillierPf}
		common.Logger.Debugf("party %s: paillier keygen done. took %s\n", round, time.Since(start))
		ch <- paillier
	}(paiCh)

	// generate auxilliary RSA primes for ZKPs later on
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

	cmt, err := cmt.NewHashCommitment(uiGx, uiGy)
	if err != nil {
		return err
	}

	pai := <-paiCh
	rsa := <-rsaCh
	if rsa == nil {
		return errors.New("RSA generation failed!")
	}

	// collect and BROADCAST commitments, paillier pk + proof; round 1 message
	p1msg := NewKGRound1CommitMessage(round.partyID, cmt.C, &pai.PublicKey, pai.Proof, &rsa.PublicKey)

	// for this P: SAVE generated secrets, commitments, paillier vars; for round 2
	round.temp.Ui = ui
	round.temp.DeCommitUiG = cmt.D
	round.save.PaillierSk = pai.PrivateKey
	round.save.PaillierPk = &pai.PublicKey
	round.save.RSAKey = rsa

	round.temp.kgRound1CommitMessages[round.partyID.Index] = &p1msg
	round.out <- p1msg
	return nil
}

func (round *round1) canAccept(msg types.Message) bool {
	if msg, ok := msg.(*KGRound1CommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round1) update() (bool, error) {
	// guard - VERIFY received paillier pk/proofs for all Pj
	for j, msg := range round.temp.kgRound1CommitMessages {
		if round.ok[j] { continue }
		if !round.canAccept(msg) {
			return false, nil
		}
		if ok := msg.PaillierPf.Verify(&msg.PaillierPk); !ok {
			return false, round.wrapError(fmt.Errorf("verify paillier proof failed (from party %s)", msg.From))
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) canProceed() bool {
	if !round.started { return false }
	for _, ok := range round.ok {
		if !ok { return false }
	}
	return true
}

func (round *round1) nextRound() round {
	round.started = false
	return &round2{round}
}

// `ok` tracks parties which have been verified by update()
func (round *round1) resetOk() {
	for j := range round.ok {
		round.ok[j] = false
	}
}
