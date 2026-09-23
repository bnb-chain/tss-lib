// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/hashicorp/go-multierror"
	errors2 "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/tss"
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
	round.save.Xi = new(big.Int).Mod(xi, round.Params().EC().Params().N)

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
		ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		// 6-8.
		go func(j int, ch chan<- vssOut) {
			// 4-9.
			KGCj := round.temp.KGCs[j]
			r2msg2 := round.temp.kgRound2Message2s[j].Content().(*KGRound2Message2)
			KGDj := r2msg2.UnmarshalDeCommitment()
			// SECURITY (SRC-2026-925): enforce the exact decommitment length.
			// ECDSA reaches PjVs via PjShare.Verify (which checks len) and the
			// later Vc[c].Add(PjVs[c]) indexing; guarding here keeps the path
			// uniform with the EdDSA fix and rejects a short/empty decommitment
			// (e.g. a 1-element [r]) before any out-of-range indexing.
			//
			// It runs BEFORE DeCommit, which hashes every part it is handed, and
			// nothing upstream bounds how many arrive: ValidateBasic calls
			// NonEmptyMultiBytes with no expected length and cannot supply one,
			// because the length is a function of the threshold and the message
			// layer does not know it. Here the threshold IS known, so this is
			// both the exact bound and the cheap place for it. The accept set is
			// unchanged -- D[0] is the commitment randomness, so a payload of
			// (t+1)*2 is exactly (t+1)*2+1 parts on the wire.
			if len(KGDj) != (round.Threshold()+1)*2+1 {
				ch <- vssOut{errors.New("de-commitment verify failed"), nil}
				return
			}
			cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: KGDj}
			ok, flatPolyGs := cmtDeCmt.DeCommit()
			if !ok || flatPolyGs == nil {
				ch <- vssOut{errors.New("de-commitment verify failed"), nil}
				return
			}
			PjVs, err := crypto.UnFlattenECPoints(round.Params().EC(), flatPolyGs)
			if err != nil {
				ch <- vssOut{err, nil}
				return
			}
			// SECURITY (SRC-2026-926): ModProof verification is mandatory.
			// A missing or invalid Paillier ModProof is a hard reject. The
			// NoProofMod compatibility bypass was removed.
			//
			// What it attests is the Blum-integer shape of N — N ≡ 1 mod 4 and a
			// product of exactly two prime powers — and that is all
			// ProofMod.Verify(Session, N) (crypto/modproof/proof.go#Verify) can
			// attest, because N is its only statement input. It is NOT the only
			// check on this modulus, and it does not establish the absence of
			// small factors: that is FacProof's statement
			// (crypto/facproof/proof.go#Verify), verified below in this same
			// handler and likewise unconditional since the NoProofFac switch was
			// removed. Naming one check "the only" one is the kind of claim this
			// file cannot support about a codebase it does not enumerate.
			modProof, err := r2msg2.UnmarshalModProof()
			if err != nil {
				ch <- vssOut{errors.New("modProof verify failed"), nil}
				return
			}
			if ok = modProof.Verify(ContextJ, round.save.PaillierPKs[j].N); !ok {
				ch <- vssOut{errors.New("modProof verify failed"), nil}
				return
			}
			// Verify the ModProof for the peer's NTilde. Also mandatory.
			// SCOPE: the verifier is ProofMod.Verify(Session, N)
			// (crypto/modproof/proof.go#Verify), whose only statement input is
			// the modulus, so this attests properties of NTildej alone
			// (Blum-integer shape). It does NOT attest that NTildej is a
			// product of safe primes: safe-primality is a property of
			// NTildej's two prime factors — for each factor f, that (f-1)/2
			// is prime — and those factors never enter Verify, which receives
			// only their product. It therefore does not by itself exclude an
			// NTildej whose multiplicative group has smooth order, and it
			// constrains neither h1 nor h2, which are not its inputs. For the
			// peer's ring, <h1> == <h2> is established by the two-directional
			// DLN proof pair instead — dlnproof.Proof.Verify(Session, h1, h2,
			// N) (crypto/dlnproof/proof.go#Verify) — verified in
			// round_2.go#Start, by the VerifyDLNProof1 and VerifyDLNProof2
			// calls.
			nTildeModProof, err := r2msg2.UnmarshalNTildeModProof()
			if err != nil {
				ch <- vssOut{errors.New("nTildeModProof verify failed"), nil}
				return
			}
			if ok = nTildeModProof.Verify(ContextJ, round.save.NTildej[j]); !ok {
				ch <- vssOut{errors.New("nTildeModProof verify failed"), nil}
				return
			}
			r2msg1 := round.temp.kgRound2Message1s[j].Content().(*KGRound2Message1)
			PjShare := vss.Share{
				Threshold: round.Threshold(),
				ID:        round.PartyID().KeyInt(),
				Share:     r2msg1.UnmarshalShare(),
			}
			if ok = PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok {
				ch <- vssOut{errors.New("vss verify failed"), nil}
				return
			}
			// FacProof verification is mandatory — the legacy "old parties may
			// not send a facProof" bypass (NoProofFac) was removed alongside
			// NoProofMod (SRC-2026-926). It is not redundant with the ModProof
			// verified above: the two cover different properties of the modulus.
			facProof, err := r2msg1.UnmarshalFacProof()
			if err != nil {
				ch <- vssOut{errors.New("facProof verify failed"), nil}
				return
			}
			if ok = facProof.Verify(ContextJ, round.EC(), round.save.PaillierPKs[j].N, round.save.NTildei,
				round.save.H1i, round.save.H2i); !ok {
				ch <- vssOut{errors.New("facProof verify failed"), nil}
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
		var multiErr error
		if len(culprits) > 0 {
			for _, vssResult := range vssResults {
				if vssResult.unWrappedErr != nil {
					multiErr = multierror.Append(multiErr, vssResult.unWrappedErr)
				}
			}
			return round.WrapError(multiErr, culprits...)
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
		modQ := common.ModInt(round.Params().EC().Params().N)
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		bigXj := round.save.BigXj
		for j := 0; j < round.PartyCount(); j++ {
			Pj := round.Parties().IDs()[j]
			kj := Pj.KeyInt()
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
	ecdsaPubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "public key is not on the curve"))
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	common.Logger.Debugf("%s public key: %x", round.PartyID(), ecdsaPubKey)

	// BROADCAST paillier proof for Pi
	ki := round.PartyID().KeyInt()
	proof := round.save.PaillierSK.Proof(ki, ecdsaPubKey)
	r3msg := NewKGRound3Message(round.PartyID(), proof)
	round.temp.kgRound3Messages[PIdx] = r3msg
	round.out <- r3msg
	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.kgRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		// proof check is in round 4
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
