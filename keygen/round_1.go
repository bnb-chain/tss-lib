package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	PaillierModulusLen = 2048
	// RSA also 2048-bit modulus; two 1024-bit primes
	RSAModulusLen = 2048
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *LocalPartyTempData, out chan<- tss.Message) tss.Round {
	return &round1{
		&base{params, save, temp, out, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOk()

	pIdx := round.PartyID().Index

	// prepare for concurrent Paillier, RSA key generation
	paiCh := make(chan *paillier.PrivateKey)
	rsaCh := make(chan *rsa.PrivateKey)

	// 4. generate Paillier public key "Ei", private key and proof
	go func(ch chan<- *paillier.PrivateKey) {
		start := time.Now()
		PiPaillierSk, _ := paillier.GenerateKeyPair(PaillierModulusLen) // sk contains pk
		common.Logger.Debugf("party %s: paillier keygen done. took %s\n", round, time.Since(start))
		ch <- PiPaillierSk
	}(paiCh)

	// 5-7. generate auxiliary RSA primes for ZKPs later on
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

	// 1. calculate "partial" key share ui, make commitment -> (C, D)
	ui := random.GetRandomPositiveInt(tss.EC().Params().N)
	round.temp.ui = ui
	round.save.Ui = ui // TODO: !!!delete!!! just for testing

	// errors can be thrown in the following code; consume chans to end goroutines here
	rsa, pai := <-rsaCh, <-paiCh

	// 2. compute the vss shares
	ids := round.Parties().IDs().Keys()
	polyGs, shares, err := vss.Create(round.Params().Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err)
	}
	round.save.Ks = ids

	// security: the original ui may be discarded
	ui = big.NewInt(0)

	pGFlat, err := crypto.FlattenECPoints(polyGs.PolyG)
	if err != nil {
		return round.WrapError(err)
	}
	cmt := cmt.NewHashCommitment(pGFlat...)
	if err != nil {
		return round.WrapError(err)
	}

	// 9-11. compute h1, h2 (uses RSA primes)
	if rsa == nil {
		return round.WrapError(errors.New("RSA generation failed"))
	}

	NTildei, h1i, h2i, err := GenerateNTildei(rsa.Primes[:2])
	if err != nil {
		return round.WrapError(err)
	}
	round.save.NTildej[pIdx] = NTildei
	round.save.H1j[pIdx], round.save.H2j[pIdx] = h1i, h2i

	// for this P: SAVE
	// - shareID
	// - Shamir PolyGs
	// - our set of Shamir shares
	round.save.ShareID = ids[pIdx]
	round.temp.polyGs = polyGs
	round.temp.shares = shares

	// for this P: SAVE de-commitments, paillier keys for round 2
	round.save.PaillierSk = pai
	round.save.PaillierPks[pIdx] = &pai.PublicKey
	round.temp.deCommitPolyG = cmt.D

	// BROADCAST commitments, paillier pk + proof; round 1 message
	r1msg := NewKGRound1CommitMessage(round.PartyID(), cmt.C, &pai.PublicKey, NTildei, h1i, h2i)
	round.temp.kgRound1CommitMessages[pIdx] = &r1msg
	round.out <- r1msg
	return nil
}

func (round *round1) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*KGRound1CommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound1CommitMessages {
		if round.ok[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

func GenerateNTildei(rsaPrimes []*big.Int) (NTildei, h1i, h2i *big.Int, err error) {
	if len(rsaPrimes) < 2 {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: needs two primes, got %d", len(rsaPrimes))
	}
	NTildei = new(big.Int).Mul(rsaPrimes[0], rsaPrimes[1])
	h1 := random.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	h2 := random.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	return NTildei, h1, h2, nil
}
