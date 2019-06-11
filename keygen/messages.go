package keygen

import (
	"crypto/rsa"
	"math/big"

	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/types"
)

type (
	// KGRound1CommitMessage represents a BROADCAST message sent during Round 1 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound1CommitMessage struct {
		types.MessageMetadata
		Commitment cmt.HashCommitment // cannot be pointers due to wire_test
		PaillierPk paillier.PublicKey
		RSAModulus rsa.PublicKey
		NTildei,
		H1i, H2i *big.Int
	}

	// KGRound2VssMessage represents a P2P message sent to each party during Round 2 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound2VssMessage struct {
		types.MessageMetadata
		PiShare *vss.Share
	}

	// KGRound2DeCommitMessage represents a BROADCAST message sent to each party during Round 2 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound2DeCommitMessage struct {
		types.MessageMetadata
		DeCommitment cmt.HashDeCommitment
	}

	// KGRound3PaillierProveMessage represents a BROADCAST message sent to each party during Round 3 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	KGRound3PaillierProveMessage struct {
		types.MessageMetadata
		Proof paillier.Proof2
	}
)

// ----- //

var _ types.Message = (*KGRound1CommitMessage)(nil)

func NewKGRound1CommitMessage(
	from *types.PartyID,
	ct cmt.HashCommitment,
	paillierPk *paillier.PublicKey,
	NTildei, h1i, h2i *big.Int,
) KGRound1CommitMessage {
	return KGRound1CommitMessage{
		MessageMetadata: types.MessageMetadata{
			To:      nil, // broadcast
			From:    from,
			MsgType: "KGRound1CommitMessage",
		},
		Commitment: ct,
		PaillierPk: *paillierPk,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
	}
}

func (msg KGRound1CommitMessage) ValidateBasic() bool {
	return msg.Commitment.Cmp(big.NewInt(0)) != 0 &&
		msg.PaillierPk.N.Cmp(big.NewInt(0)) != 0 &&
		msg.PaillierPk.NSquare().Cmp(big.NewInt(0)) != 0 &&
		msg.NTildei.Cmp(big.NewInt(0)) != 0 &&
		msg.H1i.Cmp(big.NewInt(0)) != 0 &&
		msg.H2i.Cmp(big.NewInt(0)) != 0
}

// ----- //

var _ types.Message = (*KGRound2VssMessage)(nil)

func NewKGRound2VssMessage(
	to, from *types.PartyID,
	share *vss.Share,
) KGRound2VssMessage {
	return KGRound2VssMessage{
		MessageMetadata: types.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "KGRound2VssMessage",
		},
		PiShare: share,
	}
}

func (msg KGRound2VssMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}

// ----- //

var _ types.Message = (*KGRound2DeCommitMessage)(nil)

func NewKGRound2DeCommitMessage(
	from *types.PartyID,
	deCommitment cmt.HashDeCommitment,
) KGRound2DeCommitMessage {
	return KGRound2DeCommitMessage{
		MessageMetadata: types.MessageMetadata{
			To:      nil, // broadcast
			From:    from,
			MsgType: "KGRound2DeCommitMessage",
		},
		DeCommitment: deCommitment,
	}
}

func (msg KGRound2DeCommitMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}

// ----- //

var _ types.Message = (*KGRound3PaillierProveMessage)(nil)

func NewKGRound3PaillierProveMessage(
	from *types.PartyID,
	proof paillier.Proof2,
) KGRound3PaillierProveMessage {
	return KGRound3PaillierProveMessage{
		MessageMetadata: types.MessageMetadata{
			To:      nil, // broadcast
			From:    from,
			MsgType: "KGRound3PaillierProveMessage",
		},
		Proof: proof,
	}
}

func (msg KGRound3PaillierProveMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}

// ----- //
