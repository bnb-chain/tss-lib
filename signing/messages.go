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
		C1_ji  *big.Int
		Pi1_ji *mta.ProveMtaBob
		C2_ji  *big.Int
		Pi2_ji *mta.ProveMtaBob
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
	return true
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
	return true
}

func NewSignRound2MtAMidMessage(
	to, from *tss.PartyID,
	c1_ji *big.Int,
	pi1_ji *mta.ProveMtaBob,
	c2_ji *big.Int,
	pi2_ji *mta.ProveMtaBob,
) SignRound2MtAMidMessage {
	return SignRound2MtAMidMessage{
		MessageMetadata: tss.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "SignRound2MtAMidMessage",
		},
		C1_ji:  c1_ji,
		Pi1_ji: pi1_ji,
		C2_ji:  c2_ji,
		Pi2_ji: pi2_ji,
	}
}

func (round SignRound2MtAMidMessage) ValidateBasic() bool {
	return true
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

func (round SignRound3Message) ValidateBasic() bool {
	return true
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

func (round SignRound4DecommitMessage) ValidateBasic() bool {
	return true
}
