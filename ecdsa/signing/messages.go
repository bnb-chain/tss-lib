// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/golang/protobuf/proto"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message1)(nil),
		(*SignRound1Message2)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message)(nil),
		(*SignRound4Message)(nil),
		(*SignRound5Message)(nil),
		(*SignRound6Message)(nil),
		(*SignRound7Message)(nil),
	}
)

func init() {
	proto.RegisterType((*SignRound1Message1)(nil), tss.ECDSAProtoNamePrefix+"sign.Round1Message1")
	proto.RegisterType((*SignRound1Message2)(nil), tss.ECDSAProtoNamePrefix+"sign.Round1Message2")
	proto.RegisterType((*SignRound2Message)(nil), tss.ECDSAProtoNamePrefix+"sign.Round2Message")
	proto.RegisterType((*SignRound3Message)(nil), tss.ECDSAProtoNamePrefix+"sign.Round3Message")
	proto.RegisterType((*SignRound4Message)(nil), tss.ECDSAProtoNamePrefix+"sign.Round4Message")
	proto.RegisterType((*SignRound5Message)(nil), tss.ECDSAProtoNamePrefix+"sign.Round5Message")
	proto.RegisterType((*SignRound6Message)(nil), tss.ECDSAProtoNamePrefix+"sign.Round6Message")
	proto.RegisterType((*SignRound7Message)(nil), tss.ECDSAProtoNamePrefix+"sign.Round7Message")
}

// ----- //

func NewSignRound1Message1(
	to, from *tss.PartyID,
	c *big.Int,
	proof *mta.RangeProofAlice,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBz := proof.Bytes()
	content := &SignRound1Message1{
		C:               c.Bytes(),
		RangeProofAlice: pfBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetC()) &&
		common.NonEmptyMultiBytes(m.GetRangeProofAlice(), mta.RangeProofAliceBytesParts)
}

func (m *SignRound1Message1) UnmarshalC() *big.Int {
	return new(big.Int).SetBytes(m.GetC())
}

func (m *SignRound1Message1) UnmarshalRangeProofAlice() (*mta.RangeProofAlice, error) {
	return mta.RangeProofAliceFromBytes(m.GetRangeProofAlice())
}

// ----- //

func NewSignRound1Message2(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message2{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message2) ValidateBasic() bool {
	return m.Commitment != nil &&
		common.NonEmptyBytes(m.GetCommitment())
}

func (m *SignRound1Message2) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewSignRound2Message(
	to, from *tss.PartyID,
	c1Ji *big.Int,
	pi1Ji *mta.ProofBob,
	c2Ji *big.Int,
	pi2Ji *mta.ProofBobWC,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBob := pi1Ji.Bytes()
	pfBobWC := pi2Ji.Bytes()
	content := &SignRound2Message{
		C1:         c1Ji.Bytes(),
		C2:         c2Ji.Bytes(),
		ProofBob:   pfBob[:],
		ProofBobWc: pfBobWC[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetC1()) &&
		common.NonEmptyBytes(m.GetC2()) &&
		common.NonEmptyMultiBytes(m.GetProofBob(), mta.ProofBobBytesParts) &&
		common.NonEmptyMultiBytes(m.GetProofBobWc(), mta.ProofBobWCBytesParts)
}

func (m *SignRound2Message) UnmarshalProofBob() (*mta.ProofBob, error) {
	return mta.ProofBobFromBytes(m.GetProofBob())
}

func (m *SignRound2Message) UnmarshalProofBobWC() (*mta.ProofBobWC, error) {
	return mta.ProofBobWCFromBytes(m.GetProofBobWc())
}

// ----- //

func NewSignRound3Message(
	from *tss.PartyID,
	deltaI *big.Int,
	tI *big.Int,
	tProof *zkp.TProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message{
		DeltaI:       deltaI.Bytes(),
		TI:           tI.Bytes(),
		TProofAlphaX: tProof.Alpha.X().Bytes(),
		TProofAlphaY: tProof.Alpha.Y().Bytes(),
		TProofT:      tProof.T.Bytes(),
		TProofU:      tProof.U.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetDeltaI()) &&
		common.NonEmptyBytes(m.GetTI()) &&
		common.NonEmptyBytes(m.GetTProofAlphaX()) &&
		common.NonEmptyBytes(m.GetTProofAlphaY()) &&
		common.NonEmptyBytes(m.GetTProofT()) &&
		common.NonEmptyBytes(m.GetTProofU())
}

func (m *SignRound3Message) UnmarshalTProof() (*zkp.TProof, error) {
	alpha, err := crypto.NewECPoint(
		tss.EC(),
		new(big.Int).SetBytes(m.GetTProofAlphaX()),
		new(big.Int).SetBytes(m.GetTProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &zkp.TProof{
		Alpha: alpha,
		T:     new(big.Int).SetBytes(m.GetTProofT()),
		U:     new(big.Int).SetBytes(m.GetTProofU()),
	}, nil
}

// ----- //

func NewSignRound4Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &SignRound4Message{
		DeCommitment: dcBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 3)
}

func (m *SignRound4Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewSignRound5Message(
	from *tss.PartyID,
	Ri *crypto.ECPoint,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound5Message{
		RIX: Ri.X().Bytes(),
		RIY: Ri.Y().Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound5Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetRIX()) &&
		common.NonEmptyBytes(m.GetRIY())
}

func (m *SignRound5Message) UnmarshalRI() (*crypto.ECPoint, error) {
	return crypto.NewECPoint(tss.EC(),
		new(big.Int).SetBytes(m.GetRIX()),
		new(big.Int).SetBytes(m.GetRIY()))
}

// ----- //

func NewSignRound6Message(
	from *tss.PartyID,
	sI *big.Int,
	proof *zkp.STProof,

) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound6Message{
		SI:            sI.Bytes(),
		StProofAlphaX: proof.Alpha.X().Bytes(),
		StProofAlphaY: proof.Alpha.Y().Bytes(),
		StProofBetaX:  proof.Beta.X().Bytes(),
		StProofBetaY:  proof.Beta.Y().Bytes(),
		StProofT:      proof.T.Bytes(),
		StProofU:      proof.U.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound6Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetSI()) &&
		common.NonEmptyBytes(m.GetStProofAlphaX()) &&
		common.NonEmptyBytes(m.GetStProofAlphaY()) &&
		common.NonEmptyBytes(m.GetStProofBetaX()) &&
		common.NonEmptyBytes(m.GetStProofBetaY()) &&
		common.NonEmptyBytes(m.GetStProofT()) &&
		common.NonEmptyBytes(m.GetStProofU())
}

func (m *SignRound6Message) UnmarshalSTProof() (*zkp.STProof, error) {
	alpha, err := crypto.NewECPoint(
		tss.EC(),
		new(big.Int).SetBytes(m.GetStProofAlphaX()),
		new(big.Int).SetBytes(m.GetStProofAlphaY()))
	if err != nil {
		return nil, err
	}
	beta, err := crypto.NewECPoint(
		tss.EC(),
		new(big.Int).SetBytes(m.GetStProofBetaX()),
		new(big.Int).SetBytes(m.GetStProofBetaY()))
	if err != nil {
		return nil, err
	}
	return &zkp.STProof{
		Alpha: alpha,
		Beta:  beta,
		T:     new(big.Int).SetBytes(m.GetStProofT()),
		U:     new(big.Int).SetBytes(m.GetStProofU()),
	}, nil
}

// ----- //

func NewSignRound7Message(
	from *tss.PartyID,
	si *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound7Message{
		SI: si.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound7Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.SI)
}
