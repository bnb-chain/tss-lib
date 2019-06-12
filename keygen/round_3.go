package keygen

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/types"
)

type (
	// convenience structure returned through the channel below
	r3ChOut struct {
		unWrappedErr error
		pjPolyGs     []*types.ECPoint
	}
)

func (round *round3) start() *keygenError {
	if round.started {
		return round.wrapError(errors.New("round already started"), nil)
	}
	round.number = 3
	round.started = true
	round.resetOk()

	Ps := round.p2pCtx.Parties()
	PIdx := round.partyID.Index

	// 1,9. calculate xi
	xi := round.temp.shares[PIdx].Share
	for j := range Ps {
		if j == PIdx { continue }
		share := round.temp.kgRound2VssMessages[j].PiShare.Share
		xi = new(big.Int).Add(xi, share)
	}
	round.save.Xi = xi

	// 2-3.
	Vc := make([]*types.ECPoint, round.params().threshold)
	for c := range Vc {
		Vc[c] = round.temp.polyGs.PolyG[c] // ours
	}

	// 4-11.
	chs := make([]chan r3ChOut, len(Ps))
	for i := range chs {
		if i == PIdx { continue }
		chs[i] = make(chan r3ChOut)
	}
	for j := range Ps {
		if j == PIdx { continue }
		// 6-8.
		go func(j int, ch chan<- r3ChOut) {
			// 4-9.
			KGCj := round.temp.KGCs[j]
			r2msg2 := round.temp.kgRound2DeCommitMessages[j]
			KGDj := r2msg2.DeCommitment
			cmtDeCmt := commitments.HashCommitDecommit{C: *KGCj, D: KGDj}
			ok, flatPolyGs, err := cmtDeCmt.DeCommit()
			if err != nil {
				ch <- r3ChOut{err, nil}
				return
			}
			if !ok || flatPolyGs == nil {
				ch <- r3ChOut{errors.New("de-commitment verify failed"), nil}
				return
			}
			PjPolyGs, err := types.UnFlattenECPoints(flatPolyGs)
			if err != nil {
				ch <- r3ChOut{err, nil}
				return
			}
			PjShare := round.temp.kgRound2VssMessages[j].PiShare
			if ok = PjShare.Verify(round.params().threshold, PjPolyGs); !ok {
				ch <- r3ChOut{errors.New("vss verify failed"), nil}
				return
			}
			// (9) handled above
			ch <- r3ChOut{nil, PjPolyGs}
		}(j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)
	r3ChOuts := make([]r3ChOut, len(chs))
	for i := range chs {
		if i == PIdx { continue }
		r3ChOuts[i] = <- chs[i]
	}
	for j, Pj := range Ps {
		if j == PIdx { continue }
		if r3ChOuts[j].unWrappedErr != nil {
			return round.wrapError(r3ChOuts[j].unWrappedErr, Pj)
		}
		// 10-11.
		PjPolyGs := r3ChOuts[j].pjPolyGs
		for c := 0; c < round.params().threshold; c++ {
			VcX, VcY := EC().Add(Vc[c].X(), Vc[c].Y(), PjPolyGs[c].X(), PjPolyGs[c].Y())
			Vc[c] = types.NewECPoint(VcX, VcY)
		}
	}

	// 12-16. compute Xj for each Pj
	bigXj := round.save.BigXj
	for j, Pj := range Ps {
		XjX, XjY := Vc[0].X(), Vc[0].Y()
		z := (*big.Int)(nil)
		for c := 1; c < round.params().threshold; c++ {
			// z = kj^c
			z = new(big.Int).Exp(Pj.Key, big.NewInt(int64(c)), ec.N)
			// Xj = Xj * Vcz^z
			VczX, VczY := EC().ScalarMult(Vc[c].X(), Vc[c].Y(), z.Bytes())
			XjX, XjY = EC().Add(XjX, XjY, VczX, VczY)
		}
		bigXj[j] = types.NewECPoint(XjX, XjY)
	}
	round.save.BigXj = bigXj

	// 17. compute and SAVE the ECDSA public key `y`
	ecdsaPubKey := types.NewECPoint(Vc[0].X(), Vc[0].Y())
	if !ecdsaPubKey.IsOnCurve(ec) {
		return round.wrapError(errors.New("public key is not on the curve"), nil)
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	common.Logger.Debugf("%s public key: %x", round.partyID, ecdsaPubKey)
	common.Logger.Debugf("%s private share xi: %x", round.partyID, xi)

	// BROADCAST paillier proof for Pi
	ki := round.partyID.Key
	proof := round.save.PaillierSk.Proof2(ki, ecdsaPubKey)
	r3msg := NewKGRound3PaillierProveMessage(round.partyID, proof)
	round.temp.kgRound3PaillierProveMessage[PIdx] = &r3msg
	round.out <- r3msg
	return nil
}

func (round *round3) canAccept(msg types.Message) bool {
	if msg, ok := msg.(*KGRound3PaillierProveMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round3) update() (bool, *keygenError) {
	for j, msg := range round.temp.kgRound3PaillierProveMessage {
		if round.ok[j] { continue }
		if !round.canAccept(msg) {
			return false, nil
		}
		// proof check is in round 4
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) nextRound() round {
	round.started = false
	return &round4{round}
}
