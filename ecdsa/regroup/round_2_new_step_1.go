package regroup

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allOldOK()

	if !round.ReGroupParams().IsNewCommittee() {
		return nil
	}

	Pi := round.PartyID()
	i := Pi.Index

	// prepare for concurrent Paillier and RSA key generation
	paiCh := make(chan *paillier.PrivateKey)
	rsaCh := make(chan *rsa.PrivateKey)

	// generate Paillier public key "Ei", private key and proof
	go func(ch chan<- *paillier.PrivateKey) {
		start := time.Now()
		PiPaillierSk, _ := paillier.GenerateKeyPair(keygen.PaillierModulusLen) // sk contains pk
		common.Logger.Debugf("party %s: paillier keygen done. took %s\n", round.PartyID(), time.Since(start))
		ch <- PiPaillierSk
	}(paiCh)

	// generate auxiliary RSA primes for ZKPs later on
	go func(ch chan<- *rsa.PrivateKey) {
		start := time.Now()
		pk, err := rsa.GenerateMultiPrimeKey(rand.Reader, 2, keygen.RSAModulusLen)
		if err != nil {
			common.Logger.Errorf("RSA generation error: %s", err)
			ch <- nil
		}
		common.Logger.Debugf("party %s: rsa keygen done. took %s\n", round.PartyID(), time.Since(start))
		ch <- pk
	}(rsaCh)

	// 2. "broadcast" "ACK" members of the OLD committee
	r2msg1 := NewDGRound2Message2(
		round.OldParties().IDs().Exclude(round.PartyID()), round.PartyID())
	round.temp.dgRound2Message2s[i] = r2msg1
	round.out <- r2msg1

	// consume chans to end goroutines
	paiSK, rsaSK := <-paiCh, <-rsaCh
	if rsaSK == nil {
		return round.WrapError(errors.New("RSA generation failed"), Pi)
	}

	NTildei, h1i, h2i, err := crypto.GenerateNTildei([2]*big.Int{rsaSK.Primes[0], rsaSK.Primes[1]})
	if err != nil {
		return round.WrapError(err, Pi)
	}

	paillierPf := paiSK.Proof(Pi.Key, round.save.ECDSAPub)
	r2msg2 := NewDGRound2Message1(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		&paiSK.PublicKey, paillierPf, NTildei, h1i, h2i)
	round.temp.dgRound2Message1s[i] = r2msg2
	round.out <- r2msg2

	// for this P: SAVE de-commitments, paillier keys for round 2
	round.save.PaillierSk = paiSK
	round.save.PaillierPks[i] = &paiSK.PublicKey
	round.save.NTildej[i] = NTildei
	round.save.H1j[i], round.save.H2j[i] = h1i, h2i

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if round.ReGroupParams().IsNewCommittee() {
		if _, ok := msg.Content().(*DGRound2Message1); ok {
			return msg.IsBroadcast()
		}
	}
	if round.ReGroupParams().IsOldCommittee() {
		if _, ok := msg.Content().(*DGRound2Message2); ok {
			return msg.IsBroadcast() && msg.IsToOldCommittee()
		}
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	if round.ReGroupParams().IsOldCommittee() && round.ReGroupParameters.IsNewCommittee() {
		// accept messages from new -> old committee
		for j, msg1 := range round.temp.dgRound2Message2s {
			if round.newOK[j] {
				continue
			}
			if msg1 == nil || !round.CanAccept(msg1) {
				return false, nil
			}
			// accept message from new -> committee
			msg2 := round.temp.dgRound2Message1s[j]
			if msg2 == nil || !round.CanAccept(msg2) {
				return false, nil
			}
			round.newOK[j] = true
		}
	} else if round.ReGroupParams().IsOldCommittee() {
		// accept messages from new -> old committee
		for j, msg := range round.temp.dgRound2Message2s {
			if round.newOK[j] {
				continue
			}
			if msg == nil || !round.CanAccept(msg) {
				return false, nil
			}
			round.newOK[j] = true
		}
	} else if round.ReGroupParams().IsNewCommittee() {
		// accept messages from new -> new committee
		for j, msg := range round.temp.dgRound2Message1s {
			if round.newOK[j] {
				continue
			}
			if msg == nil || !round.CanAccept(msg) {
				return false, nil
			}
			round.newOK[j] = true
		}
	} else {
		return false, round.WrapError(errors.New("this party is not in the old or the new committee"), round.PartyID())
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
