// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"
	"time"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/paillier"
)

var (
	// mtaTimingProtection provides response time normalization for MtA operations.
	// This is a defense-in-depth measure against timing side-channel attacks.
	// The target duration should exceed the maximum expected computation time.
	mtaTimingProtection = common.NewTimingProtection(
		200*time.Millisecond, // Target duration for Paillier decrypt operations
		20*time.Millisecond,  // Jitter range
	)

	// errMtAShareVerification is the single error returned by AliceEnd and
	// AliceEndWC for every rejection: an invalid range proof, a failed
	// decryption, or a plaintext outside the expected output range.
	//
	// Rejections are deliberately indistinguishable to the peer. The specific
	// cause goes to the local debug log; the returned value carries no
	// distinguishing information, and callers fold it into a single round-level
	// error.
	errMtAShareVerification = errors.New("mta: share verification failed")
)

// alphaPrmInRange reports whether a decrypted MtA plaintext lies within the
// range a protocol-conforming counterparty can produce, [0, q^6).
//
// The range proofs verified beforehand bound the magnitude of the prover's
// responses, which is not the same as bounding the value that comes back out of
// the decryption, so the output is checked directly.
//
// The window has ample margin: a conforming run yields
// alphaPrm = a*b + betaPrm < q^4 + q^5 < q^6 (1536 bits), while the Paillier
// modulus is at least 2^2047. The cut may sit anywhere in the ~768-bit gap
// between those two, so it is not sensitive to the exact exponent.
//
// The check is applied at both AliceEnd and AliceEndWC, which are reached from
// different call sites and must be treated independently. It is made on the
// decrypted plaintext rather than on the individual proof witnesses because the
// plaintext is the value actually consumed downstream: one check there covers
// every route by which it can be formed.
func alphaPrmInRange(alphaPrm, q *big.Int) bool {
	if alphaPrm.Sign() < 0 {
		return false
	}
	q6 := new(big.Int).Exp(q, big.NewInt(6), nil)
	return alphaPrm.Cmp(q6) < 0
}

func AliceInit(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	a, NTildeB, h1B, h2B *big.Int,
	rand io.Reader,
) (cA *big.Int, pf *RangeProofAlice, err error) {
	cA, rA, err := pkA.EncryptAndReturnRandomness(rand, a)
	if err != nil {
		return nil, nil, err
	}
	pf, err = ProveRangeAlice(Session, ec, pkA, cA, NTildeB, h1B, h2B, a, rA, rand)
	return cA, pf, err
}

// ErrRangeProofVerify signals that BobMid / BobMidWC rejected the peer's
// supplied RangeProofAlice. Callers should attribute this error to the
// peer Pj (not the local party). Wrapped via fmt.Errorf for errors.Is.
//
// That attribution is only sound because ProveRangeAlice refuses to hand out a
// proof whose ring-side values this verifier rejects: the ring being verified
// against is the LOCAL party's, so without that refusal a peer could reach this
// line by honestly proving into a ring the local party itself chose. See
// ErrCounterpartyRingUnusable.
var ErrRangeProofVerify = errors.New("RangeProofAlice.Verify() returned false")

// ErrCounterpartyRingUnusable signals that the (NTilde, h1, h2) ring the
// COUNTERPARTY supplied does not admit a proof that same counterparty would
// accept: either the ring fails the shape conditions its own verifier applies,
// or a value this party computed IN that ring is one that verifier rejects.
// Callers should attribute it to the counterparty that supplied the ring, not to
// the local party that built the proof.
//
// It exists because of an asymmetry that is easy to miss. Every proof in this
// package is built under the COUNTERPARTY's ring and verified by that same
// counterparty: Alice's range proof uses (NTildeB, h1B, h2B) and Bob checks it;
// Bob's proof uses (NTildeA, h1A, h2A) and Alice checks it. So "your proof did
// not verify" does not on its own say whose input decided the outcome -- the
// party that supplies the ring is also the party that judges the result, and a
// ring that makes a correctly computed proof unacceptable turns into a complaint
// against the party that computed it. Detecting the ring-decided case HERE,
// before anything is sent, is what keeps the honest prover from being named for
// its counterparty's parameters. It is the mirror image of ErrRangeProofVerify.
var ErrCounterpartyRingUnusable = errors.New("the counterparty's NTilde ring does not admit a verifiable proof")

func BobMid(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
	rand io.Reader,
) (beta, cB, betaPrm *big.Int, piB *ProofBob, err error) {
	if !pf.Verify(Session, ec, pkA, NTildeB, h1B, h2B, cA) {
		err = ErrRangeProofVerify
		return
	}
	q := ec.Params().N
	q5 := new(big.Int).Mul(q, q)  // q^2
	q5 = new(big.Int).Mul(q5, q5) // q^4
	q5 = new(big.Int).Mul(q5, q)  // q^5
	betaPrm = common.GetRandomPositiveInt(rand, q5)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(rand, betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = common.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBob(Session, ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand, rand)
	return
}

func BobMidWC(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
	B *crypto.ECPoint,
	rand io.Reader,
) (beta, cB, betaPrm *big.Int, piB *ProofBobWC, err error) {
	if !pf.Verify(Session, ec, pkA, NTildeB, h1B, h2B, cA) {
		err = ErrRangeProofVerify
		return
	}
	q := ec.Params().N
	q5 := new(big.Int).Mul(q, q)  // q^2
	q5 = new(big.Int).Mul(q5, q5) // q^4
	q5 = new(big.Int).Mul(q5, q)  // q^5
	betaPrm = common.GetRandomPositiveInt(rand, q5)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(rand, betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = common.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBobWC(Session, ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand, B, rand)
	return
}

func AliceEnd(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBob,
	h1A, h2A, cA, cB, NTildeA *big.Int,
	sk *paillier.PrivateKey,
) (*big.Int, error) {
	if !pf.Verify(Session, ec, pkA, NTildeA, h1A, h2A, cA, cB) {
		common.Logger.Debugf("mta: AliceEnd rejected: ProofBob.Verify() returned false")
		return nil, errMtAShareVerification
	}

	q := ec.Params().N

	// Timing protection runs unconditionally so Paillier Decrypt's response
	// time is normalised regardless of whether the constant-time exponent
	// path is in use; the padding is the primary side-channel mitigation
	// and must not depend on caller opt-in.
	//
	// The range check runs inside the protected closure so the rejecting path is
	// padded to the same target duration as the accepting one.
	alphaPrm, err := mtaTimingProtection.ProtectBigInt(func() (*big.Int, error) {
		pt, err := sk.Decrypt(cB)
		if err != nil {
			common.Logger.Debugf("mta: AliceEnd rejected: Paillier decrypt failed: %v", err)
			return nil, errMtAShareVerification
		}
		if !alphaPrmInRange(pt, q) {
			common.Logger.Debugf("mta: AliceEnd rejected: decrypted share outside the expected range")
			return nil, errMtAShareVerification
		}
		return pt, nil
	})
	if err != nil {
		return nil, err
	}

	return new(big.Int).Mod(alphaPrm, q), nil
}

func AliceEndWC(
	Session []byte,
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBobWC,
	B *crypto.ECPoint,
	cA, cB, NTildeA, h1A, h2A *big.Int,
	sk *paillier.PrivateKey,
) (*big.Int, error) {
	if !pf.Verify(Session, ec, pkA, NTildeA, h1A, h2A, cA, cB, B) {
		common.Logger.Debugf("mta: AliceEndWC rejected: ProofBobWC.Verify() returned false")
		return nil, errMtAShareVerification
	}

	q := ec.Params().N

	// Timing protection runs unconditionally so Paillier Decrypt's response
	// time is normalised regardless of whether the constant-time exponent
	// path is in use; the padding is the primary side-channel mitigation
	// and must not depend on caller opt-in.
	//
	// The range check runs inside the protected closure so the rejecting path is
	// padded to the same target duration as the accepting one.
	alphaPrm, err := mtaTimingProtection.ProtectBigInt(func() (*big.Int, error) {
		pt, err := sk.Decrypt(cB)
		if err != nil {
			common.Logger.Debugf("mta: AliceEndWC rejected: Paillier decrypt failed: %v", err)
			return nil, errMtAShareVerification
		}
		if !alphaPrmInRange(pt, q) {
			common.Logger.Debugf("mta: AliceEndWC rejected: decrypted share outside the expected range")
			return nil, errMtAShareVerification
		}
		return pt, nil
	})
	if err != nil {
		return nil, err
	}

	return new(big.Int).Mod(alphaPrm, q), nil
}
