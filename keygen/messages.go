package keygen

import (
	"crypto/rsa"

	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/schnorrZK"
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
		PaillierPf paillier.Proof
		RSAModulus rsa.PublicKey
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
		VssParams    *vss.Params
		PolyGs       *vss.PolyGs
		DeCommitment cmt.HashDeCommitment
	}

	// KGRound3ZKUProofMessage
	// len == (NodeCnt - 1)
	KGRound3ZKUProofMessage struct {
		types.MessageMetadata
		ZKUProof *schnorrZK.ZKProof
	}
)

func NewKGRound1CommitMessage(
		from *types.PartyID,
		ct cmt.HashCommitment,
		paillierPk *paillier.PublicKey,
		paillierPf *paillier.Proof,
		rsaPk *rsa.PublicKey) KGRound1CommitMessage {
	return KGRound1CommitMessage{
		MessageMetadata: types.MessageMetadata{
			To:      nil,  // broadcast
			From:    from,
			MsgType: "KGRound1CommitMessage",
		},
		Commitment: ct,
		PaillierPk: *paillierPk,
		PaillierPf: *paillierPf,
		RSAModulus: *rsaPk,
	}
}

func NewKGRound2VssMessage(
		to, from *types.PartyID,
		share *vss.Share) KGRound2VssMessage {
	return KGRound2VssMessage{
		MessageMetadata: types.MessageMetadata{
			To:      to,
			From:    from,
			MsgType: "KGRound2VssMessage",
		},
		PiShare: share,
	}
}

func NewKGRound2DeCommitMessage(
		from *types.PartyID,
		vssParams *vss.Params,
		polyGs *vss.PolyGs,
		deCommitment cmt.HashDeCommitment) KGRound2DeCommitMessage {
	return KGRound2DeCommitMessage{
		MessageMetadata: types.MessageMetadata{
			To:      nil, // broadcast
			From:    from,
			MsgType: "KGRound2DeCommitMessage",
		},
		VssParams:    vssParams,
		PolyGs:       polyGs,
		DeCommitment: deCommitment,
	}
}

func NewKGRound3ZKUProofMessage(
		from *types.PartyID,
		ZKUProof *schnorrZK.ZKProof) KGRound3ZKUProofMessage {
	return KGRound3ZKUProofMessage{
		MessageMetadata: types.MessageMetadata{
			To:      nil,  // broadcast
			From:    from,
			MsgType: "KGRound3ZKUProofMessage",
		},
		ZKUProof: ZKUProof,
	}
}
