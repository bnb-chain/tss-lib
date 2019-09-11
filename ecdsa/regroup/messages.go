package regroup

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
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

// ----- //

func NewDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct, xkct cmt.HashCommitment,
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "DGRound1Message",
		From:    from,
		To:      to,
	}
	msg := DGRound1Message{
		EcdsaPubX:       ecdsaPub.X().Bytes(),
		EcdsaPubY:       ecdsaPub.Y().Bytes(),
		VCommitment:     vct.Bytes(),
		XAndKCommitment: xkct.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
}

func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.EcdsaPubX) &&
		common.NonEmptyBytes(m.EcdsaPubY) &&
		common.NonEmptyBytes(m.VCommitment) &&
		common.NonEmptyBytes(m.XAndKCommitment)
}

func (m *DGRound1Message) UnmarshalECDSAPub() *crypto.ECPoint {
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
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "DGRound2Message1",
		From:    from,
		To:      to,
	}
	paiPfBzs := common.BigIntsToBytes(paillierPf)
	msg := DGRound2Message1{
		PaillierN:     paillierPK.N.Bytes(),
		PaillierProof: paiPfBzs,
		NTilde:        NTildei.Bytes(),
		H1:            H1i.Bytes(),
		H2:            H2i.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType:        "DGRound2Message2",
		From:           from,
		To:             to,
		ToOldCommittee: true,
	}
	msg := DGRound2Message2{}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
}

func (msg DGRound2Message2) ValidateBasic() bool {
	return true
}

// ----- //

func NewDGRound3Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "DGRound3Message1",
		From:    from,
		To:      []*tss.PartyID{to},
	}
	msg := DGRound3Message1{
		Share: share.Share.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "DGRound3Message2",
		From:    from,
		To:      to,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	xAndKDctBzs := common.BigIntsToBytes(xkdct)
	msg := DGRound3Message2{
		VDecommitment:     vDctBzs,
		XAndKDecommitment: xAndKDctBzs,
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
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
