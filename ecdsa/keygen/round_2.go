// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"github.com/bnb-chain/tss-lib/v4/crypto/facproof"
	"github.com/bnb-chain/tss-lib/v4/crypto/modproof"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

const (
	paillierBitsLen = 2048
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	common.Logger.Debugf(
		"%s Setting up DLN verification with concurrency level of %d",
		round.PartyID(),
		round.Concurrency(),
	)
	dlnVerifier := NewDlnProofVerifier(round.Concurrency())

	i := round.PartyID().Index

	// 6. verify dln proofs, store r1 message pieces, ensure uniqueness of h1j, h2j
	h1H2Map := make(map[string]struct{}, len(round.temp.kgRound1Messages)*2)
	dlnProof1FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	dlnProof2FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	wg := new(sync.WaitGroup)
	for j, msg := range round.temp.kgRound1Messages {
		r1msg := msg.Content().(*KGRound1Message)
		H1j, H2j, NTildej, paillierPKj := r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde(),
			r1msg.UnmarshalPaillierPK()
		if paillierPKj.N.BitLen() != paillierBitsLen {
			return round.WrapError(errors.New("got paillier modulus with insufficient bits for this party"), msg.GetFrom())
		}
		if H1j.Cmp(H2j) == 0 {
			return round.WrapError(errors.New("h1j and h2j were equal for this party"), msg.GetFrom())
		}
		if NTildej.BitLen() != paillierBitsLen {
			return round.WrapError(errors.New("got NTildej with insufficient bits for this party"), msg.GetFrom())
		}
		h1JHex, h2JHex := hex.EncodeToString(H1j.Bytes()), hex.EncodeToString(H2j.Bytes())
		if _, found := h1H2Map[h1JHex]; found {
			return round.WrapError(errors.New("this h1j was already used by another party"), msg.GetFrom())
		}
		if _, found := h1H2Map[h2JHex]; found {
			return round.WrapError(errors.New("this h2j was already used by another party"), msg.GetFrom())
		}
		h1H2Map[h1JHex], h1H2Map[h2JHex] = struct{}{}, struct{}{}

		wg.Add(2)
		_j := j
		_msg := msg

		dlnVerifier.VerifyDLNProof1(round.temp.ssid, r1msg, H1j, H2j, NTildej, func(isValid bool) {
			if !isValid {
				dlnProof1FailCulprits[_j] = _msg.GetFrom()
			}
			wg.Done()
		})
		dlnVerifier.VerifyDLNProof2(round.temp.ssid, r1msg, H2j, H1j, NTildej, func(isValid bool) {
			if !isValid {
				dlnProof2FailCulprits[_j] = _msg.GetFrom()
			}
			wg.Done()
		})
	}
	wg.Wait()
	for _, culprit := range append(dlnProof1FailCulprits, dlnProof2FailCulprits...) {
		if culprit != nil {
			return round.WrapError(errors.New("dln proof verification failed"), culprit)
		}
	}
	// save NTilde_j, h1_j, h2_j, ...
	for j, msg := range round.temp.kgRound1Messages {
		if j == i {
			continue
		}
		r1msg := msg.Content().(*KGRound1Message)
		paillierPK, H1j, H2j, NTildej, KGC := r1msg.UnmarshalPaillierPK(),
			r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde(),
			r1msg.UnmarshalCommitment()
		round.save.PaillierPKs[j] = paillierPK // used in round 4
		round.save.NTildej[j] = NTildej
		round.save.H1j[j], round.save.H2j[j] = H1j, H2j
		round.temp.KGCs[j] = KGC
	}

	// 5. p2p send share ij to Pj
	shares := round.temp.shares
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	for j, Pj := range round.Parties().IDs() {

		// FacProof generation is unconditional — the NoProofFac compatibility
		// switch was removed alongside NoProofMod (SRC-2026-926). The zero-filled
		// placeholder proof is gone; every peer receives a real proof.
		facProof, err := facproof.NewProof(ContextI, round.EC(), round.save.PaillierSK.N, round.save.NTildej[j],
			round.save.H1j[j], round.save.H2j[j], round.save.PaillierSK.P, round.save.PaillierSK.Q, round.Rand())
		if err != nil {
			return round.WrapError(err, round.PartyID())
		}
		r2msg1 := NewKGRound2Message1(Pj, round.PartyID(), shares[j], facProof)
		// do not send to this Pj, but store for round 3
		if j == i {
			round.temp.kgRound2Message1s[j] = r2msg1
			continue
		}
		round.out <- r2msg1
	}

	// 7. BROADCAST de-commitments of Shamir poly*G
	// SECURITY (SRC-2026-926): ModProof is mandatory — the NoProofMod
	// compatibility switch was removed. Always generate the Paillier ModProof
	// (Blum-integer attestation) and the NTilde ModProof.
	modProof, err := modproof.NewProof(ContextI, round.save.PaillierSK.N,
		round.save.PaillierSK.P, round.save.PaillierSK.Q, round.Rand())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	// nTildeModProof is a ModProof over this party's own NTilde.
	// SCOPE: the verifier is ProofMod.Verify(Session, N)
	// (crypto/modproof/proof.go#Verify), whose only statement input is the
	// modulus N, so the proof can attest properties of N alone (Blum-integer
	// shape). It does NOT attest that NTilde is a product of safe primes:
	// safe-primality is a property of NTilde's two prime factors — for each
	// factor f, that (f-1)/2 is prime — and those factors never enter Verify,
	// which receives only their product. It also constrains neither h1 nor
	// h2, which are not its inputs at all. For a peer's ring, <h1> == <h2> is
	// established by the two-directional DLN proof pair instead —
	// dlnproof.Proof.Verify(Session, h1, h2, N) (crypto/dlnproof/proof.go#Verify),
	// verified at round_2.go#Start above, by the VerifyDLNProof1 and
	// VerifyDLNProof2 calls: proof 1 gives h2 in <h1>, proof 2 gives h1 in
	// <h2>.
	// NTilde = (2p+1)(2q+1); LocalPreParams.P, Q store the Germain primes
	// p, q (used for the DLN proof's subgroup order), NOT the safe-prime
	// factors of NTilde. Derive the safe primes 2p+1, 2q+1 here so the
	// ModProof is built from the actual factors of NTilde.
	one := big.NewInt(1)
	safePrimeP := new(big.Int).Add(new(big.Int).Lsh(round.save.LocalPreParams.P, 1), one)
	safePrimeQ := new(big.Int).Add(new(big.Int).Lsh(round.save.LocalPreParams.Q, 1), one)
	nTildeModProof, err := modproof.NewProof(ContextI, round.save.NTildei,
		safePrimeP, safePrimeQ, round.Rand())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	r2msg2 := NewKGRound2Message2(round.PartyID(), round.temp.deCommitPolyG, modProof, nTildeModProof)
	round.temp.kgRound2Message2s[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*KGRound2Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// guard - VERIFY de-commit for all Pj
	ret := true
	for j, msg := range round.temp.kgRound2Message1s {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		msg2 := round.temp.kgRound2Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
