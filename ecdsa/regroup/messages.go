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
		ECDSAPub *crypto.ECPoint // used as security parameter for commitment 2.
		VCommitment,
		XAndKCommitment cmt.HashCommitment
	}

	DGRound2NewCommitteeACKMessage struct {
		tss.MessageMetadata
	}

	DGRound2NewCommitteePaillierPublicKeyMessage struct {
		tss.MessageMetadata
		paillierPK *paillier.PublicKey
		paillierPf paillier.Proof
		NTildei,
		H1i,
		H2i *big.Int
	}

	DGRound3OldCommitteeShareMessage struct {
		tss.MessageMetadata
		Share *vss.Share
	}

	DGRound3OldCommitteeDeCommitMessage struct {
		tss.MessageMetadata
		VDeCommitment,
		XAndKDeCommitment cmt.HashDeCommitment
	}
)

// ----- //

func NewDGRound1OldCommitteeCommitMessage(
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct, xkct cmt.HashCommitment,
) DGRound1OldCommitteeCommitMessage {
	return DGRound1OldCommitteeCommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "DGRound1OldCommitteeCommitMessage",
		},
		ECDSAPub:        ecdsaPub,
		VCommitment:     vct,
		XAndKCommitment: xkct,
	}
}

func (msg DGRound1OldCommitteeCommitMessage) ValidateBasic() bool {
	return msg.ECDSAPub != nil &&
		msg.VCommitment != nil &&
		msg.XAndKCommitment != nil &&
		msg.ECDSAPub.ValidateBasic()
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
	return true
}

// ----- //

func NewDGRound2NewCommitteePaillierPublicKeyMessage(
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	paillierPf paillier.Proof,
	NTildei,
	H1i,
	H2i *big.Int,
) DGRound2NewCommitteePaillierPublicKeyMessage {
	return DGRound2NewCommitteePaillierPublicKeyMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "DGRound2NewCommitteePaillierPublicKeyMessage",
		},
		paillierPK: paillierPK,
		paillierPf: paillierPf,
		NTildei:    NTildei,
		H1i:        H1i,
		H2i:        H2i,
	}
}

func (msg DGRound2NewCommitteePaillierPublicKeyMessage) ValidateBasic() bool {
	return msg.paillierPK != nil &&
		msg.paillierPf != nil && // TODO implement Paillier proof ValidateBasic()
		msg.NTildei != nil &&
		msg.H1i != nil &&
		msg.H2i != nil
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
	return msg.Share != nil &&
		msg.Share.Share != nil &&
		msg.Share.ID != nil
}

// ----- //

func NewDGRound3OldCommitteeDeCommitMessage(
	to []*tss.PartyID,
	from *tss.PartyID,
	vdct, xkdct cmt.HashDeCommitment,
) DGRound3OldCommitteeDeCommitMessage {
	return DGRound3OldCommitteeDeCommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "DGRound3OldCommitteeDeCommitMessage",
		},
		VDeCommitment:     vdct,
		XAndKDeCommitment: xkdct,
	}
}

func (msg DGRound3OldCommitteeDeCommitMessage) ValidateBasic() bool {
	return msg.VDeCommitment != nil &&
		msg.XAndKDeCommitment != nil
}
