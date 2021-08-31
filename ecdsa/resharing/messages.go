// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/dlnproof"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
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
	}
)

// ----- //

func NewDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct cmt.HashCommitment,
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
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.EcdsaPubX) &&
		common.NonEmptyBytes(m.EcdsaPubY) &&
		common.NonEmptyBytes(m.VCommitment)
}

func (m *DGRound1Message) UnmarshalECDSAPub() (*crypto.ECPoint, error) {
	return crypto.NewECPoint(
		tss.EC(),
		new(big.Int).SetBytes(m.EcdsaPubX),
		new(big.Int).SetBytes(m.EcdsaPubY))
}

func (m *DGRound1Message) UnmarshalVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetVCommitment())
}

// ----- //

func NewDGRound2Message1(
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	paillierPf paillier.Proof,
	NTildei, H1i, H2i *big.Int,
	dlnProof1, dlnProof2 *dlnproof.Proof,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	paiPfBzs := common.BigIntsToBytes(paillierPf[:])
	dlnProof1Bz, err := dlnProof1.Serialize()
	if err != nil {
		return nil, err
	}
	dlnProof2Bz, err := dlnProof2.Serialize()
	if err != nil {
		return nil, err
	}
	content := &DGRound2Message1{
		PaillierN:     paillierPK.N.Bytes(),
		PaillierProof: paiPfBzs,
		NTilde:        NTildei.Bytes(),
		H1:            H1i.Bytes(),
		H2:            H2i.Bytes(),
		Dlnproof_1:    dlnProof1Bz,
		Dlnproof_2:    dlnProof2Bz,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *DGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.PaillierProof) &&
		common.NonEmptyBytes(m.PaillierN) &&
		common.NonEmptyBytes(m.NTilde) &&
		common.NonEmptyBytes(m.H1) &&
		common.NonEmptyBytes(m.H2) &&
		// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
		common.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnproof.Iterations*2)) &&
		common.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnproof.Iterations*2))
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

func (m *DGRound2Message1) UnmarshalPaillierProof() paillier.Proof {
	var pf paillier.Proof
	ints := common.MultiBytesToBigInts(m.PaillierProof)
	copy(pf[:], ints[:paillier.ProofIters])
	return pf
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

func NewDGRound4Message(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &DGRound4Message{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message) ValidateBasic() bool {
	return true
}
