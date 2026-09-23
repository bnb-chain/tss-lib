// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"github.com/bnb-chain/tss-lib/v4/crypto/facproof"
	"github.com/bnb-chain/tss-lib/v4/crypto/modproof"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	cmt "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/v4/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1Message)(nil),
		(*KGRound2Message1)(nil),
		(*KGRound2Message2)(nil),
		(*KGRound3Message)(nil),
	}
)

// ----- //

func NewKGRound1Message(
	from *tss.PartyID,
	ct cmt.HashCommitment,
	paillierPK *paillier.PublicKey,
	nTildeI, h1I, h2I *big.Int,
	dlnProof1, dlnProof2 *dlnproof.Proof,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dlnProof1Bz, err := dlnProof1.Serialize()
	if err != nil {
		return nil, err
	}
	dlnProof2Bz, err := dlnProof2.Serialize()
	if err != nil {
		return nil, err
	}
	content := &KGRound1Message{
		Commitment: ct.Bytes(),
		PaillierN:  paillierPK.N.Bytes(),
		NTilde:     nTildeI.Bytes(),
		H1:         h1I.Bytes(),
		H2:         h2I.Bytes(),
		Dlnproof_1: dlnProof1Bz,
		Dlnproof_2: dlnProof2Bz,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

// minPaillierBitLen is the lower bound on |N| for both the Paillier modulus
// and NTilde at message-decode time. GG18 §3 (defect D3) requires N > q^8
// for secp256k1-class threshold ECDSA; with q ≈ 2^256 this gives |N| ≥ 2048.
// keygen round_2.go enforces an exact bitlen of 2048 once messages reach
// the round handler, but the bitlen check at the message-validation layer
// closes the gap for any caller that runs ValidateBasic without ever
// reaching round_2 (e.g. monitoring / replay code).
const minPaillierBitLen = 2048

func (m *KGRound1Message) ValidateBasic() bool {
	if m == nil ||
		!common.NonEmptyBytes(m.GetCommitment()) ||
		!common.NonEmptyBytes(m.GetPaillierN()) ||
		!common.NonEmptyBytes(m.GetNTilde()) ||
		!common.NonEmptyBytes(m.GetH1()) ||
		!common.NonEmptyBytes(m.GetH2()) ||
		// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
		!common.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnproof.Iterations*2)) ||
		!common.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnproof.Iterations*2)) {
		return false
	}
	// Reject any peer whose PaillierN or NTilde fails the |N| ≥ 2048
	// bit-length floor (= 8·|q| for secp256k1 / GG18 D3).
	if new(big.Int).SetBytes(m.GetPaillierN()).BitLen() < minPaillierBitLen {
		return false
	}
	if new(big.Int).SetBytes(m.GetNTilde()).BitLen() < minPaillierBitLen {
		return false
	}
	return true
}

func (m *KGRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

func (m *KGRound1Message) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *KGRound1Message) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *KGRound1Message) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *KGRound1Message) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *KGRound1Message) UnmarshalDLNProof1() (*dlnproof.Proof, error) {
	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_1())
}

func (m *KGRound1Message) UnmarshalDLNProof2() (*dlnproof.Proof, error) {
	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_2())
}

// ----- //

func NewKGRound2Message1(
	to, from *tss.PartyID,
	share *vss.Share,
	proof *facproof.ProofFac,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	proofBzs := proof.Bytes()
	content := &KGRound2Message1{
		Share:    share.Share.Bytes(),
		FacProof: proofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message1) ValidateBasic() bool {
	// FacProof is now always generated (the NoProofFac compatibility switch was
	// removed), so a message without one is malformed and can be rejected here
	// rather than failing later in round 3.
	return m != nil &&
		common.NonEmptyBytes(m.GetShare()) &&
		common.NonEmptyMultiBytes(m.GetFacProof(), facproof.ProofFacBytesParts)
}

func (m *KGRound2Message1) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
}

func (m *KGRound2Message1) UnmarshalFacProof() (*facproof.ProofFac, error) {
	return facproof.NewProofFromBytes(m.GetFacProof())
}

// ----- //

func NewKGRound2Message2(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *modproof.ProofMod,
	nTildeProof *modproof.ProofMod,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	proofBzs := proof.Bytes()
	content := &KGRound2Message2{
		DeCommitment: dcBzs,
		ModProof:     proofBzs[:],
	}
	if nTildeProof != nil {
		nTildeProofBzs := nTildeProof.Bytes()
		content.NTildeModProof = nTildeProofBzs[:]
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetDeCommitment())
	// ModProof / NTildeModProof byte-part counts are not enforced here (they
	// are structurally validated when unmarshalled). round_3.go now verifies
	// both unconditionally and hard-rejects a missing/invalid proof
	// (SRC-2026-926 — the NoProofMod compatibility fallback was removed).
}

func (m *KGRound2Message2) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *KGRound2Message2) UnmarshalModProof() (*modproof.ProofMod, error) {
	return modproof.NewProofFromBytes(m.GetModProof())
}

// UnmarshalNTildeModProof returns the peer's ModProof over its NTilde.
// SCOPE: the verifier is ProofMod.Verify(Session, N)
// (crypto/modproof/proof.go#Verify), whose only statement input is the modulus,
// so the proof attests properties of NTilde alone (Blum-integer shape). It
// does NOT attest that NTilde is a product of safe primes: safe-primality is a
// property of NTilde's two prime factors — for each factor f, that (f-1)/2 is
// prime — and those factors never enter Verify, which receives only their
// product. For the peer's ring, <h1> == <h2> is established by the
// two-directional DLN proof pair instead — dlnproof.Proof.Verify(Session, h1,
// h2, N) (crypto/dlnproof/proof.go#Verify) — verified at round_2.go#Start, by the
// VerifyDLNProof1 and VerifyDLNProof2 calls.
// Returns an error if the peer shipped no/invalid proof; round_3.go treats
// that as a hard reject (SRC-2026-926 — the NoProofMod fallback was removed).
func (m *KGRound2Message2) UnmarshalNTildeModProof() (*modproof.ProofMod, error) {
	return modproof.NewProofFromBytes(m.GetNTildeModProof())
}

// ----- //

func NewKGRound3Message(
	from *tss.PartyID,
	proof paillier.Proof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pfBzs := make([][]byte, len(proof))
	for i := range pfBzs {
		if proof[i] == nil {
			continue
		}
		pfBzs[i] = proof[i].Bytes()
	}
	content := &KGRound3Message{
		PaillierProof: pfBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetPaillierProof(), paillier.ProofIters)
}

func (m *KGRound3Message) UnmarshalProofInts() paillier.Proof {
	var pf paillier.Proof
	proofBzs := m.GetPaillierProof()
	for i := range pf {
		pf[i] = new(big.Int).SetBytes(proofBzs[i])
	}
	return pf
}
