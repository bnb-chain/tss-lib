package signing

import (
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/protob"
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
		(*SignRound8Message)(nil),
		(*SignRound9Message)(nil),
	}
)

func init() {
	proto.RegisterType((*SignRound1Message1)(nil), tss.ProtoNamePrefix+"signing.SignRound1Message1")
	proto.RegisterType((*SignRound1Message2)(nil), tss.ProtoNamePrefix+"signing.SignRound1Message2")
	proto.RegisterType((*SignRound2Message)(nil), tss.ProtoNamePrefix+"signing.SignRound2Message")
	proto.RegisterType((*SignRound3Message)(nil), tss.ProtoNamePrefix+"signing.SignRound3Message")
	proto.RegisterType((*SignRound4Message)(nil), tss.ProtoNamePrefix+"signing.SignRound4Message")
	proto.RegisterType((*SignRound5Message)(nil), tss.ProtoNamePrefix+"signing.SignRound5Message")
	proto.RegisterType((*SignRound6Message)(nil), tss.ProtoNamePrefix+"signing.SignRound6Message")
	proto.RegisterType((*SignRound7Message)(nil), tss.ProtoNamePrefix+"signing.SignRound7Message")
	proto.RegisterType((*SignRound8Message)(nil), tss.ProtoNamePrefix+"signing.SignRound8Message")
	proto.RegisterType((*SignRound9Message)(nil), tss.ProtoNamePrefix+"signing.SignRound9Message")
}

// ----- //

func NewSignRound1Message1(
	to, from *tss.PartyID,
	c *big.Int,
	proof *mta.RangeProofAlice,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
		To:   []*tss.PartyID{to},
	}
	pfBz := proof.Bytes()
	content := &SignRound1Message1{
		C:               c.Bytes(),
		RangeProofAlice: pfBz[:],
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: false,
		Message:     any,
	}
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
	meta := tss.MessageMetadata{
		From: from,
	}
	content := &SignRound1Message2{
		Commitment: commitment.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: true,
		Message:     any,
	}
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
	meta := tss.MessageMetadata{
		From: from,
		To:   []*tss.PartyID{to},
	}
	pfBob := pi1Ji.Bytes()
	pfBobWC := pi2Ji.Bytes()
	content := &SignRound2Message{
		C1:         c1Ji.Bytes(),
		C2:         c2Ji.Bytes(),
		ProofBob:   pfBob[:],
		ProofBobWc: pfBobWC[:],
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: false,
		Message:     any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.C1) &&
		common.NonEmptyBytes(m.C2) &&
		common.NonEmptyMultiBytes(m.ProofBob, mta.ProofBobBytesParts) &&
		common.NonEmptyMultiBytes(m.ProofBobWc, mta.ProofBobWCBytesParts)
}

func (m *SignRound2Message) UnmarshalProofBob() (*mta.ProofBob, error) {
	return mta.ProofBobFromBytes(m.ProofBob)
}

func (m *SignRound2Message) UnmarshalProofBobWC() (*mta.ProofBobWC, error) {
	return mta.ProofBobWCFromBytes(m.ProofBobWc)
}

// ----- //

func NewSignRound3Message(
	from *tss.PartyID,
	theta *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
	}
	content := &SignRound3Message{
		Theta: theta.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: true,
		Message:     any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Theta)
}

// ----- //

func NewSignRound4Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *schnorr.ZKProof,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &SignRound4Message{
		DeCommitment: dcBzs,
		ProofAlphaX:  proof.Alpha.X().Bytes(),
		ProofAlphaY:  proof.Alpha.Y().Bytes(),
		ProofT:       proof.T.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: true,
		Message:     any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 3) &&
		common.NonEmptyBytes(m.ProofAlphaX) &&
		common.NonEmptyBytes(m.ProofAlphaY) &&
		common.NonEmptyBytes(m.ProofT)
}

func (m *SignRound4Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *SignRound4Message) UnmarshalZKProof() (*schnorr.ZKProof, error) {
	point, err := crypto.NewECPoint(
		tss.EC(),
		new(big.Int).SetBytes(m.GetProofAlphaX()),
		new(big.Int).SetBytes(m.GetProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &schnorr.ZKProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetProofT()),
	}, nil
}

// ----- //

func NewSignRound5Message(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
	}
	content := &SignRound5Message{
		Commitment: commitment.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: true,
		Message:     any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound5Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Commitment)
}

func (m *SignRound5Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewSignRound6Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *schnorr.ZKProof,
	vProof *schnorr.ZKVProof,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &SignRound6Message{
		DeCommitment: dcBzs,
		ProofAlphaX:  proof.Alpha.X().Bytes(),
		ProofAlphaY:  proof.Alpha.Y().Bytes(),
		ProofT:       proof.T.Bytes(),
		VProofAlphaX: vProof.Alpha.X().Bytes(),
		VProofAlphaY: vProof.Alpha.Y().Bytes(),
		VProofT:      vProof.T.Bytes(),
		VProofU:      vProof.U.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: true,
		Message:     any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound6Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 5) &&
		common.NonEmptyBytes(m.ProofAlphaX) &&
		common.NonEmptyBytes(m.ProofAlphaY) &&
		common.NonEmptyBytes(m.ProofT) &&
		common.NonEmptyBytes(m.VProofAlphaX) &&
		common.NonEmptyBytes(m.VProofAlphaY) &&
		common.NonEmptyBytes(m.VProofT) &&
		common.NonEmptyBytes(m.VProofU)
}

func (m *SignRound6Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *SignRound6Message) UnmarshalZKProof() (*schnorr.ZKProof, error) {
	point, err := crypto.NewECPoint(
		tss.EC(),
		new(big.Int).SetBytes(m.GetProofAlphaX()),
		new(big.Int).SetBytes(m.GetProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &schnorr.ZKProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetProofT()),
	}, nil
}

func (m *SignRound6Message) UnmarshalZKVProof() (*schnorr.ZKVProof, error) {
	point, err := crypto.NewECPoint(
		tss.EC(),
		new(big.Int).SetBytes(m.GetVProofAlphaX()),
		new(big.Int).SetBytes(m.GetVProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &schnorr.ZKVProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetVProofT()),
		U:     new(big.Int).SetBytes(m.GetVProofU()),
	}, nil
}

// ----- //

func NewSignRound7Message(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
	}
	content := &SignRound7Message{
		Commitment: commitment.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: true,
		Message:     any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound7Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Commitment)
}

func (m *SignRound7Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewSignRound8Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &SignRound8Message{
		DeCommitment: dcBzs,
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: true,
		Message:     any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound8Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 5)
}

func (m *SignRound8Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewSignRound9Message(
	from *tss.PartyID,
	si *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageMetadata{
		From: from,
	}
	content := &SignRound9Message{
		S: si.Bytes(),
	}
	any, _ := ptypes.MarshalAny(content)
	msg := &protob.Message{
		IsBroadcast: true,
		Message:     any,
	}
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound9Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.S)
}

func (m *SignRound9Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.S)
}
