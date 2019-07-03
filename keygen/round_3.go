package keygen

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOk()

	Ps := round.Parties().IDs()
	PIdx := round.PartyID().Index

	// 1,9. calculate xi
	xi := big.NewInt(0).Set(round.temp.shares[PIdx].Share)
	for j := range Ps {
		if j == PIdx {
			continue
		}
		share := round.temp.kgRound2VssMessages[j].PiShare.Share
		xi = new(big.Int).Add(xi, share)
	}
	round.save.Xi = new(big.Int).Mod(xi, tss.EC().Params().N)

	// 2-3.
	Vc := make([]*crypto.ECPoint, round.Params().Threshold() + 1)
	for c := range Vc {
		Vc[c] = round.temp.polyGs.PolyG[c] // ours
	}

	// 4-11.
	type vssOut struct {
		unWrappedErr error
		pjPolyGs     []*crypto.ECPoint
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
			r2msg2 := round.temp.kgRound2DeCommitMessages[j]
			KGDj := r2msg2.DeCommitment
			cmtDeCmt := commitments.HashCommitDecommit{C: *KGCj, D: KGDj}
			ok, flatPolyGs := cmtDeCmt.DeCommit()
			if !ok || flatPolyGs == nil {
				ch <- vssOut{errors.New("de-commitment verify failed"), nil}
				return
			}
			PjPolyGs, err := crypto.UnFlattenECPoints(nil, flatPolyGs)
			if err != nil {
				ch <- vssOut{err, nil}
				return
			}
			PjShare := round.temp.kgRound2VssMessages[j].PiShare
			if ok = PjShare.Verify(round.Params().Threshold(), PjPolyGs); !ok {
				ch <- vssOut{errors.New("vss verify failed"), nil}
				return
			}
			// (9) handled above
			ch <- vssOut{nil, PjPolyGs}
		}(j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)
	vssResults := make([]vssOut, len(Ps))
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
	for j := range Ps {
		if j == PIdx {
			continue
		}
		// 10-11.
		PjPolyGs := vssResults[j].pjPolyGs
		for c := 0; c <= round.Params().Threshold(); c++ {
			VcX, VcY := tss.EC().Add(Vc[c].X(), Vc[c].Y(), PjPolyGs[c].X(), PjPolyGs[c].Y())
			Vc[c] = crypto.NewECPoint(tss.EC(), VcX, VcY)
		}
	}

	// 12-16. compute Xj for each Pj
	bigXj := round.save.BigXj
	for j, Pj := range Ps {
		var z *big.Int
		XjX, XjY := Vc[0].X(), Vc[0].Y()
		for c := 1; c <= round.Params().Threshold(); c++ {
			// z = kj^c
			z = new(big.Int).Exp(Pj.Key, big.NewInt(int64(c)), tss.EC().Params().N)
			// Xj = Xj * Vcz^z
			VczX, VczY := tss.EC().ScalarMult(Vc[c].X(), Vc[c].Y(), z.Bytes())
			XjX, XjY = tss.EC().Add(XjX, XjY, VczX, VczY)
		}
		bigXj[j] = crypto.NewECPoint(tss.EC(), XjX, XjY)
	}
	round.save.BigXj = bigXj

	// 17. compute and SAVE the ECDSA public key `y`
	ecdsaPubKey := crypto.NewECPoint(tss.EC(), Vc[0].X(), Vc[0].Y())
	if !ecdsaPubKey.IsOnCurve() {
		return round.WrapError(errors.New("public key is not on the curve"))
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	common.Logger.Debugf("%s public key: %x", round.PartyID(), ecdsaPubKey)

	// BROADCAST paillier proof for Pi
	ki := round.PartyID().Key
	proof := round.save.PaillierSk.Proof(ki, ecdsaPubKey)
	r3msg := NewKGRound3PaillierProveMessage(round.PartyID(), proof)
	round.temp.kgRound3PaillierProveMessage[PIdx] = &r3msg
	round.out <- r3msg
	return nil
}

func (round *round3) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*KGRound3PaillierProveMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound3PaillierProveMessage {
		if round.ok[j] {
			continue
		}
		if !round.CanAccept(msg) {
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
