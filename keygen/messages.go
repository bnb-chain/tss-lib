package keygen

import (
	"crypto/rsa"
	"math/big"

	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	_ tss.Message = (*KGRound1CommitMessage)(nil)
	_ tss.Message = (*KGRound2VssMessage)(nil)
	_ tss.Message = (*KGRound2DeCommitMessage)(nil)
	_ tss.Message = (*KGRound3PaillierProveMessage)(nil)

	zero = big.NewInt(0)
)

type (
	// KGRound1CommitMessage represents a BROADCAST message sent during Round 1 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound1CommitMessage struct {
		tss.MessageMetadata
		Commitment cmt.HashCommitment
		PaillierPk *paillier.PublicKey
		RSAModulus *rsa.PublicKey
		NTildei,
		H1i, H2i *big.Int
	}

	// KGRound2VssMessage represents a P2P message sent to each party during Round 2 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound2VssMessage struct {
		tss.MessageMetadata
		PiShare *vss.Share
	}

	// KGRound2DeCommitMessage represents a BROADCAST message sent to each party during Round 2 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound2DeCommitMessage struct {
		tss.MessageMetadata
		DeCommitment cmt.HashDeCommitment
	}

	// KGRound3PaillierProveMessage represents a BROADCAST message sent to each party during Round 3 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound3PaillierProveMessage struct {
		tss.MessageMetadata
		Proof paillier.Proof2
	}
)

// ----- //

func NewKGRound1CommitMessage(
	from *tss.PartyID,
	ct cmt.HashCommitment,
	paillierPk *paillier.PublicKey,
	NTildei, h1i, h2i *big.Int,
) KGRound1CommitMessage {
	return KGRound1CommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil, // broadcast
			From:    from,
			MsgType: "KGRound1CommitMessage",
		},
		Commitment: ct,
		PaillierPk: paillierPk,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
	}
}

func (msg KGRound1CommitMessage) ValidateBasic() bool {
	return msg.Commitment != nil &&
		msg.Commitment.Cmp(zero) != 0 &&
		msg.PaillierPk.N.Cmp(zero) != 0 &&
		msg.PaillierPk.NSquare().Cmp(zero) != 0 &&
		msg.NTildei.Cmp(zero) != 0 &&
		msg.H1i.Cmp(zero) != 0 &&
		msg.H2i.Cmp(zero) != 0
}

// ----- //

func NewKGRound2VssMessage(
	to, from *tss.PartyID,
	share *vss.Share,
) KGRound2VssMessage {
	return KGRound2VssMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "KGRound2VssMessage",
		},
		PiShare: share,
	}
}

func (msg KGRound2VssMessage) ValidateBasic() bool {
	return msg.PiShare != nil &&
		msg.PiShare.Threshold > 0 &&
		msg.PiShare.ID.Cmp(zero) != 0 &&
		msg.PiShare.Share.Cmp(zero) != 0
}

// ----- //

func NewKGRound2DeCommitMessage(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
) KGRound2DeCommitMessage {
	return KGRound2DeCommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil, // broadcast
			From:    from,
			MsgType: "KGRound2DeCommitMessage",
		},
		DeCommitment: deCommitment,
	}
}

func (msg KGRound2DeCommitMessage) ValidateBasic() bool {
	return msg.DeCommitment != nil &&
		len(msg.DeCommitment) > 0
}

// ----- //

func NewKGRound3PaillierProveMessage(
	from *tss.PartyID,
	proof paillier.Proof2,
) KGRound3PaillierProveMessage {
	return KGRound3PaillierProveMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil, // broadcast
			From:    from,
			MsgType: "KGRound3PaillierProveMessage",
		},
		Proof: proof,
	}
}

func (msg KGRound3PaillierProveMessage) ValidateBasic() bool {
	return msg.Proof != nil &&
		len(msg.Proof) == paillier.Proof2Iters
}
