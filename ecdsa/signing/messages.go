package signing

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go

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

// ----- //

func NewSignRound1Message1(
	to, from *tss.PartyID,
	c *big.Int,
	proof *mta.RangeProofAlice,
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound1Message1",
		From:    from,
		To:      []*tss.PartyID{to},
	}
	pfBz := proof.Bytes()
	msg := SignRound1Message1{
		C:          c.Bytes(),
		ProofAlice: pfBz[:],
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
}

func (m *SignRound1Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetC()) &&
		common.NonEmptyMultiBytes(m.GetProofAlice(), mta.RangeProofAliceBytesParts)
}

func (m *SignRound1Message1) UnmarshalRangeProofAlice() (*mta.RangeProofAlice, error) {
	return mta.RangeProofAliceFromBytes(m.ProofAlice)
}

// ----- //

func NewSignRound1Message2(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound1Message2",
		From:    from,
	}
	msg := SignRound1Message2{
		Commitment: commitment.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound2Message",
		From:    from,
		To:      []*tss.PartyID{to},
	}
	pfBob := pi1Ji.Bytes()
	pfBobWC := pi2Ji.Bytes()
	msg := SignRound2Message{
		C1:         c1Ji.Bytes(),
		C2:         c2Ji.Bytes(),
		ProofBob:   pfBob[:],
		ProofBobWc: pfBobWC[:],
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound3Message",
		From:    from,
	}
	msg := SignRound3Message{
		Theta: theta.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound4Message",
		From:    from,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	msg := SignRound4Message{
		DeCommitment: dcBzs,
		ProofAlphaX:  proof.Alpha.X().Bytes(),
		ProofAlphaY:  proof.Alpha.Y().Bytes(),
		ProofT:       proof.T.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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

func (m *SignRound4Message) UnmarshalZKProof() *schnorr.ZKProof {
	return &schnorr.ZKProof{
		Alpha: crypto.NewECPoint(
			tss.EC(),
			new(big.Int).SetBytes(m.GetProofAlphaX()),
			new(big.Int).SetBytes(m.GetProofAlphaY())),
		T: new(big.Int).SetBytes(m.GetProofT()),
	}
}

// ----- //

func NewSignRound5Message(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound5Message",
		From:    from,
	}
	msg := SignRound5Message{
		Commitment: commitment.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound6Message",
		From:    from,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	msg := SignRound6Message{
		DeCommitment: dcBzs,
		ProofAlphaX:  proof.Alpha.X().Bytes(),
		ProofAlphaY:  proof.Alpha.Y().Bytes(),
		ProofT:       proof.T.Bytes(),
		VProofAlphaX: vProof.Alpha.X().Bytes(),
		VProofAlphaY: vProof.Alpha.Y().Bytes(),
		VProofT:      vProof.T.Bytes(),
		VProofU:      vProof.U.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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

func (m *SignRound6Message) UnmarshalZKProof() *schnorr.ZKProof {
	return &schnorr.ZKProof{
		Alpha: crypto.NewECPoint(
			tss.EC(),
			new(big.Int).SetBytes(m.GetProofAlphaX()),
			new(big.Int).SetBytes(m.GetProofAlphaY())),
		T: new(big.Int).SetBytes(m.GetProofT()),
	}
}
func (m *SignRound6Message) UnmarshalZKVProof() *schnorr.ZKVProof {
	return &schnorr.ZKVProof{
		Alpha: crypto.NewECPoint(
			tss.EC(),
			new(big.Int).SetBytes(m.GetProofAlphaX()),
			new(big.Int).SetBytes(m.GetProofAlphaY())),
		T: new(big.Int).SetBytes(m.GetProofT()),
		U: new(big.Int).SetBytes(m.GetVProofU()),
	}
}

// ----- //

func NewSignRound7Message(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound7Message",
		From:    from,
	}
	msg := SignRound5Message{
		Commitment: commitment.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound8Message",
		From:    from,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	msg := SignRound8Message{
		DeCommitment: dcBzs,
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "SignRound9Message",
		From:    from,
	}
	msg := SignRound9Message{
		S: si.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
}

func (m *SignRound9Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.S)
}

func (m *SignRound9Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.S)
}
