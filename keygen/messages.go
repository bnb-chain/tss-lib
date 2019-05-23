package keygen

import (
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/schnorrZK"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/types"
)

type (
	KGMessage interface {
		GetFrom() types.PartyID
		GetTo()   types.PartyID
		GetType() string
	}

	KGMessageMetadata struct {
		To,
		From types.PartyID
		MsgType string
	}

	// C1
	// len == (NodeCnt - 1)
	KGPhase1CommitMessage struct {
		KGMessageMetadata
		Commitment cmt.HashCommitment
		PaillierPk paillier.PublicKey
	}

	// SHARE1
	// len == (NodeCnt - 1)
	KGPhase2VssMessage struct {
		KGMessageMetadata
		PolyG  *vss.PolyG
		Shares []*vss.Share
	}

	// D1
	// len == (NodeCnt - 1)
	KGPhase2DeCommitMessage struct {
		KGMessageMetadata
		VssParams    vss.Params
		DeCommitment cmt.HashDeCommitment
	}

	// ZKFACTPROOF
	// len == (NodeCnt - 1)
	KGPhase3ZKProofMessage struct {
		KGMessageMetadata
		ZKProof *paillier.Proof
	}

	// ZKUPROOF
	// len == (NodeCnt - 1)
	KGPhase3ZKUProofMessage struct {
		KGMessageMetadata
		ZKUProof *schnorrZK.ZKProof
	}
)

// ----- //

func (kgMM KGMessageMetadata) GetFrom() types.PartyID {
	return kgMM.From
}

func (kgMM KGMessageMetadata) GetTo() types.PartyID {
	return kgMM.To
}

func (kgMM KGMessageMetadata) GetType() string {
	return kgMM.MsgType
}

// ----- //

func NewKGPhase1CommitMessage(to, from *types.PartyID, ct cmt.HashCommitment, paillierPk *paillier.PublicKey) KGPhase1CommitMessage {
	// to may be `nil`
	var toToUse types.PartyID
	if to != nil {
		toToUse = *to
	}
	return KGPhase1CommitMessage{
		KGMessageMetadata: KGMessageMetadata{
			To:      toToUse,
			From:    *from,
			MsgType: "KGPhase1CommitMessage",
		},
		Commitment: ct,
		PaillierPk: *paillierPk,
	}
}

func NewKGPhase2VssMessage(to, from *types.PartyID, polyG *vss.PolyG, shares []*vss.Share) KGPhase2VssMessage {
	// to may be `nil`
	var toToUse types.PartyID
	if to != nil {
		toToUse = *to
	}
	return KGPhase2VssMessage{
		KGMessageMetadata: KGMessageMetadata{
			To:      toToUse,
			From:    *from,
			MsgType: "KGPhase2VssMessage",
		},
		PolyG:  polyG,
		Shares: shares,
	}
}

func NewKGPhase2DeCommitMessage(to, from *types.PartyID, vssParams vss.Params, deCommitment cmt.HashDeCommitment) KGPhase2DeCommitMessage {
	// to may be `nil`
	var toToUse types.PartyID
	if to != nil {
		toToUse = *to
	}
	return KGPhase2DeCommitMessage{
		KGMessageMetadata: KGMessageMetadata{
			To:      toToUse,
			From:    *from,
			MsgType: "KGPhase2DeCommitMessage",
		},
		VssParams:    vssParams,
		DeCommitment: deCommitment,
	}
}

func NewKGPhase3ZKProofMessage(to, from *types.PartyID, ZKProof *paillier.Proof) KGPhase3ZKProofMessage {
	// to may be `nil`
	var toToUse types.PartyID
	if to != nil {
		toToUse = *to
	}
	return KGPhase3ZKProofMessage{
		KGMessageMetadata: KGMessageMetadata{
			To:      toToUse,
			From:    *from,
			MsgType: "KGPhase3ZKProofMessage",
		},
		ZKProof: ZKProof,
	}
}

func NewKGPhase3ZKUProofMessage(to, from *types.PartyID, ZKUProof *schnorrZK.ZKProof) KGPhase3ZKUProofMessage {
	// to may be `nil`
	var toToUse types.PartyID
	if to != nil {
		toToUse = *to
	}
	return KGPhase3ZKUProofMessage{
		KGMessageMetadata: KGMessageMetadata{
			To:      toToUse,
			From:    *from,
			MsgType: "KGPhase3ZKUProofMessage",
		},
		ZKUProof: ZKUProof,
	}
}
