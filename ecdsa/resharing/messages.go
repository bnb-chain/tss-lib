// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	cmt "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/v4/crypto/facproof"
	"github.com/bnb-chain/tss-lib/v4/crypto/modproof"
	"github.com/bnb-chain/tss-lib/v4/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-resharing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*DGRound1Message)(nil),
		(*DGRound2Message1)(nil),
		(*DGRound2Message2)(nil),
		(*DGRound3Message1)(nil),
		(*DGRound3Message2)(nil),
		(*DGRound4Message1)(nil),
		(*DGRound4Message2)(nil),
	}
)

// ----- //

func NewDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct cmt.HashCommitment,
	ssid []byte,
	sessionNonceHash []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	content := &DGRound1Message{
		EcdsaPubX:   ecdsaPub.X().Bytes(),
		EcdsaPubY:   ecdsaPub.Y().Bytes(),
		VCommitment: vct.Bytes(),
		Ssid:        ssid,
		// See the proto comment: the new committee cannot recompute `Ssid`, so
		// this is the only value in the message it can check against something
		// of its own.
		SessionNonceHash: sessionNonceHash,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// sessionDigestMaxBytes bounds the two SHA512_256-derived fields below. Both are
// produced as common.SHA512_256i(...).Bytes(), a 32-byte digest with leading
// zeroes dropped, so 32 is the exact upper bound a conforming sender can reach
// and not a guess. It matters because neither field had one: the ssid is
// adopted into round.temp.ssid and then prefixes the Session of every
// zero-knowledge proof in the run, so its declared length is a length this party
// re-hashes on each of them.
const sessionDigestMaxBytes = 32

func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.EcdsaPubX) &&
		common.NonEmptyBytes(m.EcdsaPubY) &&
		common.NonEmptyBytes(m.VCommitment) &&
		// Required, not optional: an absent hash is exactly what a transcript
		// captured before this field existed would carry, and it must not be
		// laundered into "nothing to compare".
		common.NonEmptyBytes(m.SessionNonceHash) &&
		len(m.SessionNonceHash) <= sessionDigestMaxBytes &&
		// Upper bound only. Emptiness is deliberately NOT rejected here: round 2
		// tests it itself so that an empty declaration is refused with an
		// ssid-specific error naming the sender, instead of being dropped by the
		// message layer with no attribution.
		len(m.Ssid) <= sessionDigestMaxBytes
}

func (m *DGRound1Message) UnmarshalECDSAPub(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.EcdsaPubX),
		new(big.Int).SetBytes(m.EcdsaPubY))
}

func (m *DGRound1Message) UnmarshalVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetVCommitment())
}

func (m *DGRound1Message) UnmarshalSSID() []byte {
	return m.GetSsid()
}

// ----- //

func NewDGRound2Message1(
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	modProof *modproof.ProofMod,
	NTildei, H1i, H2i *big.Int,
	dlnProof1, dlnProof2 *dlnproof.Proof,
	nTildeModProof *modproof.ProofMod,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	modPfBzs := modProof.Bytes()
	dlnProof1Bz, err := dlnProof1.Serialize()
	if err != nil {
		return nil, err
	}
	dlnProof2Bz, err := dlnProof2.Serialize()
	if err != nil {
		return nil, err
	}
	content := &DGRound2Message1{
		PaillierN:  paillierPK.N.Bytes(),
		ModProof:   modPfBzs[:],
		NTilde:     NTildei.Bytes(),
		H1:         H1i.Bytes(),
		H2:         H2i.Bytes(),
		Dlnproof_1: dlnProof1Bz,
		Dlnproof_2: dlnProof2Bz,
	}
	if nTildeModProof != nil {
		nTildePfBzs := nTildeModProof.Bytes()
		content.NTildeModProof = nTildePfBzs[:]
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

// minResharePaillierBitLen mirrors keygen's `minPaillierBitLen` for the
// resharing path. Same GG18 §3 D3 requirement: |N| >= 2048 for secp256k1.
const minResharePaillierBitLen = 2048

func (m *DGRound2Message1) ValidateBasic() bool {
	if m == nil ||
		!common.NonEmptyBytes(m.PaillierN) ||
		!common.NonEmptyBytes(m.NTilde) ||
		!common.NonEmptyBytes(m.H1) ||
		!common.NonEmptyBytes(m.H2) ||
		// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
		!common.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnproof.Iterations*2)) ||
		!common.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnproof.Iterations*2)) ||
		// nTildeModProof is declared "Not optional" in
		// protob/ecdsa-resharing.proto and round_4_new_step_2.go already treats
		// a missing/unparseable proof as a culprit that aborts the round
		// (SRC-2026-926 removed the NoProofMod fallback). The message layer did
		// not hold up its end: an all-empty field passed here and only failed
		// three rounds later.
		//
		// This predicate is byte-for-byte the one modproof.NewProofFromBytes
		// applies (NonEmptyMultiBytes with the same ProofModBytesParts arity),
		// so it accepts exactly the proofs UnmarshalNTildeModProof can decode.
		// It therefore moves the rejection earlier without changing which
		// messages are rejected.
		!common.NonEmptyMultiBytes(m.GetNTildeModProof(), modproof.ProofModBytesParts) {
		return false
	}
	// Align with keygen's bitlen floor at the message-decode layer.
	// Round 4 also enforces the same floor; this catches malformed
	// messages earlier for any consumer that runs ValidateBasic alone.
	if new(big.Int).SetBytes(m.PaillierN).BitLen() < minResharePaillierBitLen {
		return false
	}
	if new(big.Int).SetBytes(m.NTilde).BitLen() < minResharePaillierBitLen {
		return false
	}
	return true
}

func (m *DGRound2Message1) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{
		N: new(big.Int).SetBytes(m.PaillierN),
	}
}

func (m *DGRound2Message1) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *DGRound2Message1) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *DGRound2Message1) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *DGRound2Message1) UnmarshalModProof() (*modproof.ProofMod, error) {
	return modproof.NewProofFromBytes(m.GetModProof())
}

// UnmarshalNTildeModProof returns the ModProof attesting that the peer's
// resharing NTilde is a Blum integer. Mirrors keygen's
// `KGRound2Message2.UnmarshalNTildeModProof`. Returns an error if the peer
// shipped no/invalid proof; round_4_new_step_2.go now treats that as a hard
// reject (SRC-2026-926 — the NoProofMod fallback was removed).
func (m *DGRound2Message1) UnmarshalNTildeModProof() (*modproof.ProofMod, error) {
	return modproof.NewProofFromBytes(m.GetNTildeModProof())
}

func (m *DGRound2Message1) UnmarshalDLNProof1() (*dlnproof.Proof, error) {
	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_1())
}

func (m *DGRound2Message1) UnmarshalDLNProof2() (*dlnproof.Proof, error) {
	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_2())
}

// ----- //

func NewDGRound2Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: true,
	}
	content := &DGRound2Message2{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound2Message2) ValidateBasic() bool {
	return true
}

// ----- //

func NewDGRound3Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	content := &DGRound3Message1{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Share)
}

// ----- //

func NewDGRound3Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
	vdct cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	content := &DGRound3Message2{
		VDecommitment: vDctBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.VDecommitment)
}

func (m *DGRound3Message2) UnmarshalVDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetVDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewDGRound4Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &DGRound4Message2{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message2) ValidateBasic() bool {
	return true
}

func NewDGRound4Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	proof *facproof.ProofFac,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	pfBzs := proof.Bytes()
	content := &DGRound4Message1{
		FacProof: pfBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message1) ValidateBasic() bool {
	// FacProof is now always generated (the NoProofFac compatibility switch was
	// removed), so a message without one is malformed and can be rejected here
	// rather than failing later in round 5.
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetFacProof(), facproof.ProofFacBytesParts)
}

func (m *DGRound4Message1) UnmarshalFacProof() (*facproof.ProofFac, error) {
	return facproof.NewProofFromBytes(m.GetFacProof())
}

func (m *DGRound1Message) UnmarshalSessionNonceHash() []byte {
	return m.GetSessionNonceHash()
}
