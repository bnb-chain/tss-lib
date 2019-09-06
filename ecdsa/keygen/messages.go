package keygen

import (
	"math/big"

	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages are generated from Protocol Buffers definitions
type (
	// KGRound1CommitMessage represents a BROADCAST message sent during Round 1 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound1CommitMessage = KGRound1Message

	// KGRound2VssMessage represents a P2P message sent to each party during Round 2 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound2VssMessage = KGRound2Message1

	// KGRound2DeCommitMessage represents a BROADCAST message sent to each party during Round 2 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound2DeCommitMessage = KGRound2Message2

	// KGRound3PaillierProveMessage represents a BROADCAST message sent to each party during Round 3 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound3PaillierProveMessage = KGRound3Message
)

// ----- //

func NewKGRound1CommitMessage(
	from *tss.PartyID,
	ct cmt.HashCommitment,
	paillierPK *paillier.PublicKey,
	NTildei, h1i, h2i *big.Int,
) *tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "KGRound1CommitMessage",
		From:    from,
	}
	msg := KGRound1CommitMessage{
		Commitment: ct.Bytes(),
		PaillierN:  paillierPK.N.Bytes(),
		NTilde:     NTildei.Bytes(),
		H1:         h1i.Bytes(),
		H2:         h2i.Bytes(),
	}
	return &tss.Message{meta, &msg}
}

func (msg *KGRound1CommitMessage) ValidateBasic() bool {
	return msg != nil &&
		msg.GetCommitment() != nil &&
		len(msg.GetCommitment()) > 0 &&
		msg.GetPaillierN() != nil &&
		len(msg.GetPaillierN()) > 0 &&
		msg.GetNTilde() != nil &&
		len(msg.GetNTilde()) > 0 &&
		msg.GetH1() != nil &&
		len(msg.GetH1()) > 0 &&
		msg.GetH2() != nil &&
		len(msg.GetH2()) > 0
}

func (msg *KGRound1CommitMessage) CommitmentInt() *big.Int {
	return new(big.Int).SetBytes(msg.GetCommitment())
}

func (msg *KGRound1CommitMessage) PaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(msg.GetPaillierN())}
}

func (msg *KGRound1CommitMessage) NTildeInt() *big.Int {
	return new(big.Int).SetBytes(msg.GetNTilde())
}

func (msg *KGRound1CommitMessage) H1Int() *big.Int {
	return new(big.Int).SetBytes(msg.GetH1())
}

func (msg *KGRound1CommitMessage) H2Int() *big.Int {
	return new(big.Int).SetBytes(msg.GetH2())
}

// ----- //

func NewKGRound2VssMessage(
	to, from *tss.PartyID,
	share *vss.Share,
) *tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "KGRound2VssMessage",
		From:    from,
		To:      []*tss.PartyID{to},
	}
	msg := KGRound2Message1{
		Share: share.Share.Bytes(),
	}
	return &tss.Message{meta, &msg}
}

func (msg *KGRound2VssMessage) ValidateBasic() bool {
	return msg != nil &&
		msg.GetShare() != nil &&
		len(msg.GetShare()) > 0
}

func (msg *KGRound2VssMessage) ShareInt() *big.Int {
	return new(big.Int).SetBytes(msg.Share)
}

// ----- //

func NewKGRound2DeCommitMessage(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
) *tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "KGRound2DeCommitMessage",
		From:    from,
	}
	dcBzs := make([][]byte, len(deCommitment))
	for i := range dcBzs {
		if deCommitment[i] == nil {
			continue
		}
		dcBzs[i] = deCommitment[i].Bytes()
	}
	msg := KGRound2Message2{
		DeCommitment: dcBzs,
	}
	return &tss.Message{meta, &msg}
}

func (msg *KGRound2DeCommitMessage) ValidateBasic() bool {
	second := true
	bzs := msg.GetDeCommitment()
	first := msg != nil && bzs != nil && len(bzs) > 0
	if first {
		for _, bz := range bzs {
			if bz == nil || len(bz) < 1 {
				second = false
				break
			}
		}
	}
	return first && second
}

func (msg *KGRound2DeCommitMessage) DeCommitmentInts() []*big.Int {
	bzs := msg.GetDeCommitment()
	ints := make([]*big.Int, len(bzs))
	for i := range ints {
		ints[i] = new(big.Int).SetBytes(bzs[i])
	}
	return ints
}

// ----- //

func NewKGRound3PaillierProveMessage(
	from *tss.PartyID,
	proof paillier.Proof,
) *tss.Message {
	meta := tss.MessageMetadata{
		MsgType: "KGRound3PaillierProveMessage",
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
	return &tss.Message{meta, &msg}
}

func (msg *KGRound3PaillierProveMessage) ValidateBasic() bool {
	second := true
	bzs := msg.GetPaillierProof()
	first := msg != nil && bzs != nil && len(bzs) > 0
	if first {
		for _, bz := range bzs {
			if bz == nil || len(bz) < 1 {
				second = false
				break
			}
		}
	}
	return first && second
}

func (msg *KGRound3PaillierProveMessage) GetProofInts() []*big.Int {
	bzs := msg.GetPaillierProof()
	ints := make([]*big.Int, len(bzs))
	for i := range ints {
		ints[i] = new(big.Int).SetBytes(bzs[i])
	}
	return ints
}

