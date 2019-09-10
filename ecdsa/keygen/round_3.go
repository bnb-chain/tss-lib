package keygen

import (
	"errors"
	"math/big"

	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	PIdx := round.PartyID().Index

	// 1,9. calculate xi
	xi := new(big.Int).Set(round.temp.shares[PIdx].Share)
	for j := range Ps {
		if j == PIdx {
			continue
		}
		r2msg1 := round.temp.kgRound2Message1s[j].Content().(*KGRound2Message1)
		share := r2msg1.UnmarshalShare()
		xi = new(big.Int).Add(xi, share)
	}
	round.save.Xi = new(big.Int).Mod(xi, tss.EC().Params().N)

	// 2-3.
	Vc := make(vss.Vs, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c] // ours
	}

	// 4-11.
	type vssOut struct {
		unWrappedErr error
		pjVs         vss.Vs
	}
	chs := make([]chan vssOut, len(Ps))
	for i := range chs {
		if i == PIdx {
			continue
		}
		chs[i] = make(chan vssOut)
	}
	for j := range Ps {
		if j == PIdx {
			continue
		}
		// 6-8.
		go func(j int, ch chan<- vssOut) {
			// 4-9.
			KGCj := round.temp.KGCs[j]
			r2msg2 := round.temp.kgRound2Message2s[j].Content().(*KGRound2Message2)
			KGDj := r2msg2.UnmarshalDeCommitment()
			cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: KGDj}
			ok, flatPolyGs := cmtDeCmt.DeCommit()
			if !ok || flatPolyGs == nil {
				ch <- vssOut{errors.New("de-commitment verify failed"), nil}
				return
			}
			PjVs, err := crypto.UnFlattenECPoints(tss.EC(), flatPolyGs)
			if err != nil {
				ch <- vssOut{err, nil}
				return
			}
			r2msg1 := round.temp.kgRound2Message1s[j].Content().(*KGRound2Message1)
			PjShare := vss.Share{
				Threshold: round.Threshold(),
				ID: round.PartyID().Key,
				Share: r2msg1.UnmarshalShare(),
			}
			if ok = PjShare.Verify(round.Threshold(), PjVs); !ok {
				ch <- vssOut{errors.New("vss verify failed"), nil}
				return
			}
			// (9) handled above
			ch <- vssOut{nil, PjVs}
		}(j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)
	vssResults := make([]vssOut, len(Ps))
	{
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			vssResults[j] = <-chs[j]
			// collect culprits to error out with
			if err := vssResults[j].unWrappedErr; err != nil {
				culprits = append(culprits, Pj)
			}
		}
		if len(culprits) > 0 {
			return round.WrapError(vssResults[0].unWrappedErr, culprits...)
		}
	}
	{
		var err error
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			// 10-11.
			PjVs := vssResults[j].pjVs
			for c := 0; c <= round.Threshold(); c++ {
				Vc[c], err = Vc[c].Add(PjVs[c])
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding PjVs[c] to Vc[c] resulted in a point not on the curve"), culprits...)
		}
	}

	// 12-16. compute Xj for each Pj
	{
		var err error
		modQ := common.ModInt(tss.EC().Params().N)
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		bigXj := round.save.BigXj
		for j := 0; j < round.PartyCount(); j++ {
			Pj := round.Parties().IDs()[j]
			kj := Pj.Key
			BigXj := Vc[0]
			z := new(big.Int).SetInt64(int64(1))
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
			bigXj[j] = BigXj
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), culprits...)
		}
		round.save.BigXj = bigXj
	}

	// 17. compute and SAVE the ECDSA public key `y`
	ecdsaPubKey, err := crypto.NewECPoint(tss.EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "public key is not on the curve"))
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	common.Logger.Debugf("%s public key: %x", round.PartyID(), ecdsaPubKey)

	// BROADCAST paillier proof for Pi
	ki := round.PartyID().Key
	proof := round.save.PaillierSk.Proof(ki, ecdsaPubKey)
	r3msg := NewKGRound3Message(round.PartyID(), proof)
	round.temp.kgRound3Messages[PIdx] = r3msg
	round.out <- r3msg
	return nil
}

func (round *round3) CanAccept(msg tss.Message) bool {
	if _, ok := msg.Content().(*KGRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// proof check is in round 4
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
