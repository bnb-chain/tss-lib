package signing

import (
	"math/big"

	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	SignRound1MtAInitMessage struct {
		tss.MessageMetadata
		C  *big.Int
		Pi *mta.RangeProofAlice
	}

	SignRound1CommitMessage struct {
		tss.MessageMetadata
		Commitment cmt.HashCommitment
	}

	SignRound2MtAMidMessage struct {
		tss.MessageMetadata
		C1Ji  *big.Int
		Pi1Ji *mta.ProofBob
		C2Ji  *big.Int
		Pi2Ji *mta.ProofBobWC
	}

	SignRound3Message struct {
		tss.MessageMetadata
		Thelta *big.Int
	}

	SignRound4DecommitMessage struct {
		tss.MessageMetadata
		Decommitment cmt.HashDeCommitment
		Proof        *schnorr.ZKProof
	}

	SignRound5CommitMessage struct {
		tss.MessageMetadata
		Commitment cmt.HashCommitment
	}

	SignRound6DecommitMessage struct {
		tss.MessageMetadata
		Decommitment cmt.HashDeCommitment
		Proof        *schnorr.ZKProof
		VProof       *schnorr.ZKVProof
	}

	SignRound7CommitMessage struct {
		tss.MessageMetadata
		Commitment cmt.HashCommitment
	}

	SignRound8DecommitMessage struct {
		tss.MessageMetadata
		Decommitment cmt.HashDeCommitment
	}

	SignRound9SignatureMessage struct {
		tss.MessageMetadata
		Si *big.Int
	}
)

func NewSignRound1MtAInitMessage(
	to, from *tss.PartyID,
	C *big.Int,
	Pi *mta.RangeProofAlice,
) SignRound1MtAInitMessage {
	return SignRound1MtAInitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "SignRound1MtAInitMessage",
		},
		C:  C,
		Pi: Pi,
	}
}

func (msg SignRound1MtAInitMessage) ValidateBasic() bool {
	return msg.C != nil && msg.Pi != nil && msg.Pi.ValidateBasic()
}

func NewSignRound1CommitMessage(
	from *tss.PartyID,
	Commitment cmt.HashCommitment,
) SignRound1CommitMessage {
	return SignRound1CommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil,
			From:    from,
			MsgType: "SignRound1CommitMessage",
		},
		Commitment: Commitment,
	}
}

func (msg SignRound1CommitMessage) ValidateBasic() bool {
	return msg.Commitment != nil
}

func NewSignRound2MtAMidMessage(
	to, from *tss.PartyID,
	c1Ji *big.Int,
	pi1Ji *mta.ProofBob,
	c2Ji *big.Int,
	pi2Ji *mta.ProofBobWC,
) SignRound2MtAMidMessage {
	return SignRound2MtAMidMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "SignRound2MtAMidMessage",
		},
		C1Ji:  c1Ji,
		Pi1Ji: pi1Ji,
		C2Ji:  c2Ji,
		Pi2Ji: pi2Ji,
	}
}

func (msg SignRound2MtAMidMessage) ValidateBasic() bool {
	return msg.C1Ji != nil && msg.Pi1Ji != nil && msg.Pi1Ji.ValidateBasic() && msg.C2Ji != nil && msg.Pi2Ji != nil && msg.Pi2Ji.ValidateBasic()
}

func NewSignRound3Message(
	from *tss.PartyID,
	thelta *big.Int,
) SignRound3Message {
	return SignRound3Message{
		MessageMetadata: tss.MessageMetadata{
			To:      nil,
			From:    from,
			MsgType: "SignRound3Message",
		},
		Thelta: thelta,
	}
}

func (msg SignRound3Message) ValidateBasic() bool {
	return msg.Thelta != nil
}

func NewSignRound4DecommitMessage(
	from *tss.PartyID,
	decommitment cmt.HashDeCommitment,
	proof *schnorr.ZKProof,
) SignRound4DecommitMessage {
	return SignRound4DecommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil,
			From:    from,
			MsgType: "SignRound4DecommitMessage",
		},
		Decommitment: decommitment,
		Proof:        proof,
	}
}

func (msg SignRound4DecommitMessage) ValidateBasic() bool {
	return msg.Decommitment != nil && len(msg.Decommitment) == 3 && msg.Proof != nil && msg.Proof.ValidateBasic()
}

func NewSignRound5CommitmentMessage(
	from *tss.PartyID,
	C cmt.HashCommitment,
) SignRound5CommitMessage {
	return SignRound5CommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil,
			From:    from,
			MsgType: "SignRound5CommitmentMessage",
		},
		Commitment: C,
	}
}

func (msg SignRound5CommitMessage) ValidateBasic() bool {
	return msg.Commitment != nil
}

func NewSignRound6DecommitMessage(
	from *tss.PartyID,
	D cmt.HashDeCommitment,
	Proof *schnorr.ZKProof,
	VProof *schnorr.ZKVProof,
) SignRound6DecommitMessage {
	return SignRound6DecommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil,
			From:    from,
			MsgType: "SignRound6DecommitmentMessage",
		},
		Decommitment: D,
		Proof:        Proof,
		VProof:       VProof,
	}
}

func (msg SignRound6DecommitMessage) ValidateBasic() bool {
	return msg.Decommitment != nil && len(msg.Decommitment) == 5 && msg.Proof != nil && msg.Proof.ValidateBasic() && msg.VProof != nil && msg.VProof.ValidateBasic()
}

func NewSignRound7CommitMessage(
	from *tss.PartyID,
	C cmt.HashCommitment,
) SignRound7CommitMessage {
	return SignRound7CommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil,
			From:    from,
			MsgType: "SignRound7CommitMessage",
		},
		Commitment: C,
	}
}

func (msg SignRound7CommitMessage) ValidateBasic() bool {
	return msg.Commitment != nil
}

func NewSignRound8DecommitMessage(
	from *tss.PartyID,
	D cmt.HashDeCommitment,
) SignRound8DecommitMessage {
	return SignRound8DecommitMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil,
			From:    from,
			MsgType: "SignRound8DecommitMessage",
		},
		Decommitment: D,
	}
}

func (msg SignRound8DecommitMessage) ValidateBasic() bool {
	return msg.Decommitment != nil && len(msg.Decommitment) == 5
}

func NewSignRound9SignatureMessage(
	from *tss.PartyID,
	si *big.Int,
) SignRound9SignatureMessage {
	return SignRound9SignatureMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      nil,
			From:    from,
			MsgType: "SignRound9SignatureMessage",
		},
		Si: si,
	}
}

func (msg SignRound9SignatureMessage) ValidateBasic() bool {
	return msg.Si != nil
}
