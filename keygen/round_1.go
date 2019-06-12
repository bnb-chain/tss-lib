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
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/types"
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *KGParameters, save *LocalPartySaveData, temp *LocalPartyTempData, out chan<- types.Message) round {
	return &round1{
		&base{params, save, temp, out, make([]bool, params.partyCount), false, 1}}
}

func (round *round1) start() *keygenError {
	if round.started {
		return round.wrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOk()

	pIdx := round.partyID.Index

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
	ui := random.GetRandomPositiveInt(EC().N)
	round.temp.ui = ui

	// errors can be thrown in the following code; consume chans to end goroutines here
	rsa, pai := <-rsaCh, <-paiCh

	// 2. compute the vss shares
	ids := round.p2pCtx.Parties().Keys()
	polyGs, shares, err := vss.Create(round.params().Threshold(), ui, ids)
	if err != nil {
		return round.wrapError(err)
	}

	// security: the original ui may be discarded
	ui = big.NewInt(0)

	pGFlat, err := types.FlattenECPoints(polyGs.PolyG)
	if err != nil {
		return round.wrapError(err)
	}
	cmt, err := cmt.NewHashCommitment(pGFlat...)
	if err != nil {
		return round.wrapError(err)
	}

	// 9-11. compute h1, h2 (uses RSA primes)
	if rsa == nil {
		return round.wrapError(errors.New("RSA generation failed"))
	}

	NTildei, h1i, h2i, err := generateNTildei(rsa.Primes[:2])
	if err != nil {
		return round.wrapError(err)
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
	r1msg := NewKGRound1CommitMessage(round.partyID, cmt.C, &pai.PublicKey, NTildei, h1i, h2i)
	round.temp.kgRound1CommitMessages[pIdx] = &r1msg
	round.out <- r1msg
	return nil
}

func (round *round1) canAccept(msg types.Message) bool {
	if msg, ok := msg.(*KGRound1CommitMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round1) update() (bool, *keygenError) {
	for j, msg := range round.temp.kgRound1CommitMessages {
		if round.ok[j] {
			continue
		}
		if !round.canAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) nextRound() round {
	round.started = false
	return &round2{round}
}

// ----- //

func generateNTildei(rsaPrimes []*big.Int) (NTildei, h1i, h2i *big.Int, err error) {
	if len(rsaPrimes) < 2 {
		return nil, nil, nil, fmt.Errorf("generateNTildei: needs two primes, got %d", len(rsaPrimes))
	}
	NTildei = new(big.Int).Mul(rsaPrimes[0], rsaPrimes[1])
	h1 := random.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	h2 := random.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	return NTildei, h1, h2, nil
}
