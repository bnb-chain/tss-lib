package signing

import (
	"errors"
	"fmt"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

// round 1 represents round 1 of the signing part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *LocalPartySignData, temp *LocalPartyTempData, out chan<- tss.Message) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, make([]bool, len(params.Parties().IDs())), false, 1}}
}

// missing:
// line1: m = H(M) belongs to Zq
func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	k := random.GetRandomPositiveInt(tss.EC().Params().N)
	gamma := random.GetRandomPositiveInt(tss.EC().Params().N)

	pointGamma := crypto.ScalarBaseMult(tss.EC(), gamma)
	cmt := commitments.NewHashCommitment(pointGamma.X(), pointGamma.Y())
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.point = pointGamma
	round.temp.deCommit = cmt.D

	i := round.PartyID().Index
	round.ok[i] = true

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		cA, pi, err := mta.AliceInit(round.key.PaillierPks[i], k, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}
		r1msg1 := NewSignRound1Message1(Pj, round.PartyID(), cA, pi)
		round.temp.signRound1Message1s[j] = r1msg1
		if j == i {
			continue
		}
		round.temp.cis[j] = cA
		round.out <- r1msg1
	}

	r1msg2 := NewSignRound1Message2(round.PartyID(), cmt.C)
	round.temp.signRound1Message2s[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg1 := range round.temp.signRound1Message1s {
		if msg1 == nil || round.ok[j] {
			continue
		}
		if !round.CanAccept(msg1) {
			return false, nil
		}
		msg2 := round.temp.signRound1Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks
	bigXs := round.key.BigXj

	if round.Threshold()+1 > len(ks) {
		panic(fmt.Errorf("threshold is not consistent with "))
	}
	wi, bigWs := PrepareForSigning(i, len(ks), xi, ks, bigXs)

	round.temp.w = wi
	round.temp.bigWs = bigWs
}
