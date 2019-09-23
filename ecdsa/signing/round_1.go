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

	X, Y := tss.EC().ScalarBaseMult(gamma.Bytes())
	pointGamma := crypto.NewECPoint(tss.EC(), X, Y)
	cmt := commitments.NewHashCommitment(pointGamma.X(), pointGamma.Y())
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.point = pointGamma
	round.temp.deCommit = cmt.D

	i := round.PartyID().Index
	round.ok[i] = true

	for j, Pj := range round.Parties().IDs() {
		c, pi, err := mta.AliceInit(round.key.PaillierPks[i], k, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}
		if j == i {
			continue
		}
		r1msg1 := NewSignRound1MtAInitMessage(Pj, round.PartyID(), c, pi)
		round.temp.signRound1SentMtaInitMessages[j] = &r1msg1
		round.out <- r1msg1
	}

	r1msg2 := NewSignRound1CommitMessage(round.PartyID(), cmt.C)
	round.temp.signRound1CommitMessages[i] = &r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound1MtAInitMessages {
		if round.ok[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.signRound1CommitMessages[j]
		if !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.Message) bool {
	if msg1, ok := msg.(*SignRound1MtAInitMessage); !ok || msg1 == nil {
		if msg2, ok := msg.(*SignRound1CommitMessage); !ok || msg2 == nil {
			return false
		}
	}
	return true
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
