package regroup

import (
	"math/big"

	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	// KGRound1CommitMessage represents a BROADCAST message sent during Round 1 of the ECDSA TSS keygen protocol
	// len == (NodeCnt - 1)
	DGRound1OldCommitteeCommitMessage struct {
		tss.MessageMetadata
		Commitment cmt.HashCommitment
		BigXj      []*crypto.ECPoint
		Ks         []*big.Int
	}

	DGRound2NewCommitteeACKMessage struct {
		tss.MessageMetadata
	}

	DGRound2PaillierPublicKeyMessage struct {
		tss.MessageMetadata
		paillierPK *paillier.PublicKey
	}

	DGRound3OldCommitteeShareMessage struct {
		tss.MessageMetadata
		Share *vss.Share
	}

	DGRound3OldCommitteeDeCommitMessage struct {
		tss.MessageMetadata
		DeCommitment cmt.HashDeCommitment
	}
)

// ----- //

func NewDGRound1OldCommitteeCommitMessage(
	to []*tss.PartyID,
	from *tss.PartyID,
	ct cmt.HashCommitment,
	bigXj []*crypto.ECPoint,
	ks []*big.Int,
) DGRound1OldCommitteeCommitMessage {
	return DGRound1OldCommitteeCommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "DGRound1OldCommitteeCommitMessage",
		},
		Commitment: ct,
		BigXj:      bigXj,
		Ks:         ks,
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
			To:             to,
			From:           from,
			MsgType:        "DGRound2NewCommitteeACKMessage",
			ToOldCommittee: true,
		},
	}
}

func (msg DGRound2NewCommitteeACKMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}

// ----- //

func NewDGRound2PaillierPublicKeyMessage(
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
) DGRound2PaillierPublicKeyMessage {
	return DGRound2PaillierPublicKeyMessage{
		MessageMetadata: tss.MessageMetadata{
			To:             to,
			From:           from,
			MsgType:        "DGRound2PaillierPublicKeyMessage",
			ToOldCommittee: true,
		},
		paillierPK: paillierPK,
	}
}

func (msg DGRound2PaillierPublicKeyMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}

// ----- //

func NewDGRound3OldCommitteeShareMessage(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) DGRound3OldCommitteeShareMessage {
	return DGRound3OldCommitteeShareMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      []*tss.PartyID{to},
			From:    from,
			MsgType: "DGRound3OldCommitteeShareMessage",
		},
		Share: share,
	}
}

func (msg DGRound3OldCommitteeShareMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}

// ----- //

func NewDGRound3OldCommitteeDeCommitMessage(
	to []*tss.PartyID,
	from *tss.PartyID,
	dct cmt.HashDeCommitment,
) DGRound3OldCommitteeDeCommitMessage {
	return DGRound3OldCommitteeDeCommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "DGRound3OldCommitteeDeCommitMessage",
		},
		DeCommitment: dct,
	}
}

func (msg DGRound3OldCommitteeDeCommitMessage) ValidateBasic() bool {
	return true // TODO ValidateBasic
}
