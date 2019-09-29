// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package regroup

import (
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/protob"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-regroup.pb.go

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

func init() {
	proto.RegisterType((*DGRound1Message)(nil), tss.ProtoNamePrefix+"regroup.DGRound1Message")
	proto.RegisterType((*DGRound2Message1)(nil), tss.ProtoNamePrefix+"regroup.DGRound2Message1")
	proto.RegisterType((*DGRound2Message2)(nil), tss.ProtoNamePrefix+"regroup.DGRound2Message2")
	proto.RegisterType((*DGRound3Message1)(nil), tss.ProtoNamePrefix+"regroup.DGRound3Message1")
	proto.RegisterType((*DGRound3Message2)(nil), tss.ProtoNamePrefix+"regroup.DGRound3Message2")
}

// ----- //

func NewDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct, xkct cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
		To:   to,
	}
	content := &DGRound1Message{
		EcdsaPubX:       ecdsaPub.X().Bytes(),
		EcdsaPubY:       ecdsaPub.Y().Bytes(),
		VCommitment:     vct.Bytes(),
		XAndKCommitment: xkct.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast:      true,
		IsToOldCommittee: false,
		Message:          any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.EcdsaPubX) &&
		common.NonEmptyBytes(m.EcdsaPubY) &&
		common.NonEmptyBytes(m.VCommitment) &&
		common.NonEmptyBytes(m.XAndKCommitment)
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

func (m *DGRound1Message) UnmarshalXAndKCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetXAndKCommitment())
}

// ----- //

func NewDGRound2Message1(
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	paillierPf paillier.Proof,
	NTildei,
	H1i,
	H2i *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
		To:   to,
	}
	paiPfBzs := common.BigIntsToBytes(paillierPf)
	content := &DGRound2Message1{
		PaillierN:     paillierPK.N.Bytes(),
		PaillierProof: paiPfBzs,
		NTilde:        NTildei.Bytes(),
		H1:            H1i.Bytes(),
		H2:            H2i.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast:      true,
		IsToOldCommittee: false,
		Message:          any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.PaillierProof) &&
		common.NonEmptyBytes(m.PaillierN) &&
		common.NonEmptyBytes(m.NTilde) &&
		common.NonEmptyBytes(m.H1) &&
		common.NonEmptyBytes(m.H2)
}

func (m *DGRound2Message1) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{
		N: new(big.Int).SetBytes(m.PaillierN),
	}
}

func (m *DGRound2Message1) UnmarshalPaillierProof() paillier.Proof {
	return common.MultiBytesToBigInts(m.PaillierProof)
}

// ----- //

func NewDGRound2Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
		To:   to,
	}
	content := &DGRound2Message2{}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast:      true,
		IsToOldCommittee: true,
		Message:          any,
	}
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
	meta := tss.MessageMetadata{
		From: from,
		To:   []*tss.PartyID{to},
	}
	content := &DGRound3Message1{
		Share: share.Share.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast:      false,
		IsToOldCommittee: false,
		Message:          any,
	}
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
	vdct, xkdct cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
		To:   to,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	xAndKDctBzs := common.BigIntsToBytes(xkdct)
	content := &DGRound3Message2{
		VDecommitment:     vDctBzs,
		XAndKDecommitment: xAndKDctBzs,
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast:      true,
		IsToOldCommittee: false,
		Message:          any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.VDecommitment) &&
		common.NonEmptyMultiBytes(m.XAndKDecommitment)
}

func (m *DGRound3Message2) UnmarshalVDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetVDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *DGRound3Message2) UnmarshalXAndKDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetXAndKDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}
