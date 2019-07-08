package regroup

import (
	"math/big"

	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	_ tss.Message = (*DGRound1OldCommitteeCommitMessage)(nil)

	zero = big.NewInt(0)
)

type (
	// KGRound1CommitMessage represents a BROADCAST message sent during Round 1 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	DGRound1OldCommitteeCommitMessage struct {
		tss.MessageMetadata
		Commitment cmt.HashCommitment
	}
)

// ----- //

func NewDGRound1OldCommitteeCommitMessage(
	from *tss.PartyID,
	ct cmt.HashCommitment,
) DGRound1OldCommitteeCommitMessage {
	return DGRound1OldCommitteeCommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil, // broadcast
			From:    from,
			MsgType: "KGRound1CommitMessage",
		},
		Commitment: ct,
	}
}

func (msg DGRound1OldCommitteeCommitMessage) ValidateBasic() bool {
	return true
}

// ----- //

// TODO implement other messages
