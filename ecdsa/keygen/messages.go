package keygen

import (
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"

	"github.com/binance-chain/tss-lib/common"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/binance-chain/tss-lib/tss/wire"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1Message)(nil),
		(*KGRound2Message1)(nil),
		(*KGRound2Message2)(nil),
		(*KGRound3Message)(nil),
	}
)

// The following messages are registered on the Protocol Buffers "wire" in tss/wire

// ----- //

func NewKGRound1Message(
	from *tss.PartyID,
	ct cmt.HashCommitment,
	paillierPK *paillier.PublicKey,
	nTildeI, h1I, h2I *big.Int,
) tss.Message {
	isBroadcast := true
	meta := tss.MessageMetadata{
		From:    from,
	}
	content := &KGRound1Message{
		Commitment: ct.Bytes(),
		PaillierN:  paillierPK.N.Bytes(),
		NTilde:     nTildeI.Bytes(),
		H1:         h1I.Bytes(),
		H2:         h2I.Bytes(),
	}
	bz, _ := proto.Marshal(content)
	msg := &wire.Message{
		IsBroadcast: isBroadcast,
		Message: &any.Any{
			TypeUrl: wire.ProtoNamePrefix + proto.MessageName(content),
			Value: bz,
		},
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: content, Wire: msg}
}

func (m *KGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetCommitment()) &&
		common.NonEmptyBytes(m.GetPaillierN()) &&
		common.NonEmptyBytes(m.GetNTilde()) &&
		common.NonEmptyBytes(m.GetH1()) &&
		common.NonEmptyBytes(m.GetH2())
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

// ----- //

func NewKGRound2Message1(
	to, from *tss.PartyID,
	share *vss.Share,
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "KGRound2Message1",
		From:    from,
		To:      []*tss.PartyID{to},
	}
	msg := KGRound2Message1{
		Share: share.Share.Bytes(),
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
}

func (m *KGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetShare())
}

func (m *KGRound2Message1) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
}

// ----- //

func NewKGRound2Message2(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "KGRound2Message2",
		From:    from,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	msg := KGRound2Message2{
		DeCommitment: dcBzs,
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
}

func (m *KGRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetDeCommitment())
}

func (m *KGRound2Message2) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewKGRound3Message(
	from *tss.PartyID,
	proof paillier.Proof,
) tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "KGRound3Message",
		From:    from,
	}
	pfBzs := make([][]byte, len(proof))
	for i := range pfBzs {
		if proof[i] == nil {
			continue
		}
		pfBzs[i] = proof[i].Bytes()
	}

	msg := KGRound3Message{
		PaillierProof: pfBzs,
	}
	return &tss.MessageImpl{MessageMetadata: meta, Msg: &msg}
}

func (m *KGRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetPaillierProof())
}

func (m *KGRound3Message) UnmarshalProofInts() []*big.Int {
	proofBzs := m.GetPaillierProof()
	ints := make([]*big.Int, len(proofBzs))
	for i := range ints {
		ints[i] = new(big.Int).SetBytes(proofBzs[i])
	}
	return ints
}
