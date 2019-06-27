package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

const preparePrecision = 1024

// round 1 represents round 1 of the signing part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *LocalPartySignData, temp *LocalPartyTempData, out chan<- tss.Message) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, make([]bool, params.PartyCount()), false, 1}}
}

// missing:
// line1: m = H(M) belongs to Zq
func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOk()

	k := random.GetRandomPositiveInt(tss.EC().Params().N)
	gamma := random.GetRandomPositiveInt(tss.EC().Params().N)

	X, Y := tss.EC().ScalarBaseMult(gamma.Bytes())
	pointGamma := crypto.NewECPoint(tss.EC(), X, Y)
	cmt := commitments.NewHashCommitment(pointGamma.X(), pointGamma.Y())
	//round.temp.m =
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.point = pointGamma
	round.temp.deCommit = cmt.D

	for j, Pj := range round.Parties().Parties() {
		c, pi, err := mta.AliceInit(round.key.PaillierPks[round.PartyID().Index], k, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}
		r1msg1 := NewSignRound1MtAInitMessage(Pj, round.PartyID(), c, pi)
		if j == round.PartyID().Index {
			round.temp.signRound1MtAInitMessages[j] = &r1msg1
			continue
		}
		round.temp.signRound1MtAInitMessages[round.PartyID().Index] = &r1msg1
		round.out <- r1msg1
	}

	r1msg2 := NewSignRound1CommitMessage(round.PartyID(), cmt.C)
	round.temp.signRound1CommitMessages[round.PartyID().Index] = &r1msg2
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

func (round *round1) prepare() {
	// TODO: re-visit the big.Float precision lost here
	//fmt.Printf("idx: %d, xi: %s\n", round.PartyID().Index, round.key.Xi)
	fwi := new(big.Float).SetPrec(preparePrecision).SetInt(round.key.Xi)
	//fmt.Printf("idx: %d, fwi: %s\n", round.PartyID().Index, fwi.Text('f', 100))
	for j := range round.Parties().Parties() {
		if j == round.PartyID().Index {
			continue
		}
		kj := new(big.Float).SetPrec(preparePrecision).SetInt(round.key.Ks[j])
		ki := new(big.Float).SetPrec(preparePrecision).SetInt(round.key.Ks[round.PartyID().Index])
		coefficient := new(big.Float).SetPrec(preparePrecision).Quo(kj, new(big.Float).Sub(kj, ki))
		//fmt.Printf("idx: %d, before float wi: %s\n", round.PartyID().Index, fwi.Text('f', 100))
		//fmt.Printf("idx: %d, coefficient: %s\n", round.PartyID().Index, coefficient.Text('f', 100))
		fwi = fwi.Mul(fwi, coefficient)
		//fmt.Printf("idx: %d, middle float wi: %s\n", round.PartyID().Index, fwi.Text('f', 100))
	}
	wi, ok := new(big.Int).SetString(fmt.Sprintf("%.0f", fwi), 10)
	//fmt.Printf("idx: %d, final float wi: %0.85f, final rounded wi: %s\n", round.PartyID().Index, fwi, wi.String())
	if !ok {
		panic(fmt.Errorf("failed rounding float wi"))
	}
	round.temp.w = new(big.Int).Mod(wi, tss.EC().Params().N)

	// above code is equivalent to this
	//wi := big.NewInt(0).Set(round.key.Xi)
	//for j := range round.Parties().Parties() {
	//	if j == round.PartyID().Index {
	//		continue
	//	}
	//	kj := round.key.Ks[j]
	//	ki := round.key.Ks[round.PartyID().Index]
	//	coefficient := new(big.Int).Div(kj, new(big.Int).Sub(kj, ki))
	//	wi = wi.Mul(wi, coefficient)
	//}
	//round.temp.w = wi

	// TODO: fix bigWj calculation to float operation
	for j := range round.Parties().Parties() {
		bigXjCopy := *round.key.BigXj[j]
		bigWj := &bigXjCopy
		for c := range round.Parties().Parties() {
			if j == c {
				continue
			}
			iota := new(big.Int).Mod(new(big.Int).Div(round.key.Ks[c], new(big.Int).Sub(round.key.Ks[c], round.key.Ks[j])), tss.EC().Params().N)
			newX, newY := tss.EC().ScalarMult(bigWj.X(), bigWj.Y(), iota.Bytes())
			bigWj = crypto.NewECPoint(tss.EC(), newX, newY)
		}
		round.temp.bigWs[j] = bigWj
	}
}
