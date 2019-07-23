package regroup

import (
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	// KGRound1CommitMessage represents a BROADCAST message sent during Round 1 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	DGRound1OldCommitteeCommitMessage struct {
		tss.MessageMetadata
		Commitment cmt.HashCommitment
	}

	DGRound2NewCommitteeACKMessage struct {
		tss.MessageMetadata
	}

	DGRound3ShareMessage struct {
		tss.MessageMetadata
		Share *vss.Share
	}

	DGRound3DeCommitMessage struct {
		tss.MessageMetadata
		DeCommitment cmt.HashDeCommitment
	}
)

// ----- //

func NewDGRound1OldCommitteeCommitMessage(
	to []*tss.PartyID,
	from *tss.PartyID,
	ct cmt.HashCommitment,
) DGRound1OldCommitteeCommitMessage {
	return DGRound1OldCommitteeCommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "DGRound1OldCommitteeCommitMessage",
		},
		Commitment: ct,
	}
}

func (msg DGRound1OldCommitteeCommitMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}

// ----- //

func NewDGRound2NewCommitteeACKMessage(
	to []*tss.PartyID,
	from *tss.PartyID,
) DGRound2NewCommitteeACKMessage {
	return DGRound2NewCommitteeACKMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "DGRound2NewCommitteeACKMessage",
			ToOldCommittee: true,
		},
	}
}

func (msg DGRound2NewCommitteeACKMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}

// ----- //

func NewDGRound3ShareMessage(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) DGRound3ShareMessage {
	return DGRound3ShareMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      []*tss.PartyID{to},
			From:    from,
			MsgType: "DGRound3ShareMessage",
		},
		Share: share,
	}
}

func (msg DGRound3ShareMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}

// ----- //

func NewDGRound3DeCommitMessage(
	to []*tss.PartyID,
	from *tss.PartyID,
	dct cmt.HashDeCommitment,
) DGRound3DeCommitMessage {
	return DGRound3DeCommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "DGRound3DeCommitMessage",
		},
		DeCommitment: dct,
	}
}

func (msg DGRound3DeCommitMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}
