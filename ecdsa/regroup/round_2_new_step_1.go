package regroup

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
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
	r2msg1 := NewDGRound2NewCommitteeACKMessage(
		round.Parties().IDs().Exclude(round.PartyID()), round.PartyID())
	round.temp.dgRound2NewCommitteeACKMessage[i] = &r2msg1
	round.out <- r2msg1

	// consume chans to end goroutines
	pai := <-paiCh
	r2msg2 := NewDGRound2PaillierPublicKeyMessage(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		&pai.PublicKey)
	round.temp.dgRound2PaillierPublicKeyMessage[i] = &r2msg2
	round.out <- r2msg2

	rsa := <-rsaCh
	if rsa == nil {
		return round.WrapError(errors.New("RSA generation failed"), Pi)
	}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(rsa.Primes[:2])
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// for this P: SAVE de-commitments, paillier keys for round 2
	round.save.NTildej[i] = NTildei
	round.save.H1j[i], round.save.H2j[i] = h1i, h2i
	round.save.PaillierSk = pai

	return nil
}

func (round *round2) CanAccept(msg tss.Message) bool {
	if round.ReGroupParams().IsOldCommittee() && round.ReGroupParameters.IsNewCommittee() {
		if msg1, ok := msg.(*DGRound2NewCommitteeACKMessage); !ok || msg1 == nil {
			if msg2, ok := msg.(*DGRound2PaillierPublicKeyMessage); !ok || msg2 == nil {
				return false
			}
		}
	} else if round.ReGroupParams().IsOldCommittee() {
		if msg, ok := msg.(*DGRound2NewCommitteeACKMessage); !ok || msg == nil {
			return false
		}
	} else if round.ReGroupParams().IsNewCommittee() {
		if msg, ok := msg.(*DGRound2PaillierPublicKeyMessage); !ok || msg == nil {
			return false
		}
	}
	return true
}

func (round *round2) Update() (bool, *tss.Error) {
	if round.ReGroupParams().IsOldCommittee() && round.ReGroupParameters.IsNewCommittee() {
		// accept messages from new -> old committee
		for j, msg := range round.temp.dgRound2NewCommitteeACKMessage {
			if round.newOK[j] {
				continue
			}
			if !round.CanAccept(msg) {
				return false, nil
			}
			// accept message from new -> committee
			msg2 := round.temp.dgRound2PaillierPublicKeyMessage[j]
			if !round.CanAccept(msg2) {
				return false, nil
			}
			round.newOK[j] = true
		}
	} else if round.ReGroupParams().IsOldCommittee() {
		// accept messages from new -> old committee
		for j, msg := range round.temp.dgRound2NewCommitteeACKMessage {
			if round.newOK[j] {
				continue
			}
			if !round.CanAccept(msg) {
				return false, nil
			}
			round.newOK[j] = true
		}
	} else if round.ReGroupParams().IsNewCommittee() {
		// accept messages from new -> new committee
		for j, msg := range round.temp.dgRound2PaillierPublicKeyMessage {
			if round.newOK[j] {
				continue
			}
			if !round.CanAccept(msg) {
				return false, nil
			}
			round.newOK[j] = true

			// log
			if round.PartyID().Index == 0 {
				common.Logger.Infof("new party 0 message update received: %v", round.newOK)
			}
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
