package keygen

import (
	cmt "tss-lib/crypto/commitments"
	"tss-lib/crypto/paillier"
	"tss-lib/crypto/schnorrZK"
	"tss-lib/crypto/vss"
)

type (
	KGMessage interface {
		PartyID() *PartyID
		Type()    string
	}

	KGMessageMetadata struct {
		from      *PartyID
		stateName string
	}

	// C1
	// len == (NodeCnt - 1)
	KGPhase1CommitMessage struct {
		*KGMessageMetadata
		Commitment cmt.HashCommitment
		PaillierPk *paillier.PublicKey
	}

	// SHARE1
	// len == (NodeCnt - 1)
	KGPhase2VssMessage struct {
		*KGMessageMetadata
		PolyG  *vss.PolyG
		Shares []*vss.Share
	}

	// D1
	// len == (NodeCnt - 1)
	KGPhase2DeCommitMessage struct {
		*KGMessageMetadata
		VssParams    vss.Params
		DeCommitment cmt.HashDeCommitment
	}

	// ZKFACTPROOF
	// len == (NodeCnt - 1)
	KGPhase3ZKProofMessage struct {
		*KGMessageMetadata
		ZKProof *paillier.Proof
	}

	// ZKUPROOF
	// len == (NodeCnt - 1)
	KGPhase3ZKUProofMessage struct {
		*KGMessageMetadata
		ZKUProof *schnorrZK.ZKProof
	}
)

func (kgMM *KGMessageMetadata) PartyID() *PartyID {
	return kgMM.from
}

func (kgMM *KGMessageMetadata) Type() string {
	return kgMM.stateName
}

func NewKGPhase1CommitMessage(from *PartyID, ct cmt.HashCommitment, paillierPk *paillier.PublicKey) *KGPhase1CommitMessage {
	return &KGPhase1CommitMessage{
		KGMessageMetadata: &KGMessageMetadata{
			from:      from,
			stateName: "KGPhase1CommitMessage",
		},
		Commitment: ct,
		PaillierPk: paillierPk,
	}
}

func NewKGPhase2VssMessage(from *PartyID, polyG *vss.PolyG, shares []*vss.Share) *KGPhase2VssMessage {
	return &KGPhase2VssMessage{
		KGMessageMetadata: &KGMessageMetadata{
			from:      from,
			stateName: "KGPhase2VssMessage",
		},
		PolyG:  polyG,
		Shares: shares,
	}
}

func NewKGPhase2DeCommitMessage(from *PartyID, vssParams vss.Params, deCommitment cmt.HashDeCommitment) *KGPhase2DeCommitMessage {
	return &KGPhase2DeCommitMessage{
		KGMessageMetadata: &KGMessageMetadata{
			from:      from,
			stateName: "KGPhase2DeCommitMessage",
		},
		VssParams:    vssParams,
		DeCommitment: deCommitment,
	}
}

func NewKGPhase3ZKProofMessage(from *PartyID, ZKProof *paillier.Proof) *KGPhase3ZKProofMessage {
	return &KGPhase3ZKProofMessage{
		KGMessageMetadata: &KGMessageMetadata{
			from:      from,
			stateName: "KGPhase3ZKProofMessage",
		},
		ZKProof: ZKProof,
	}
}

func NewKGPhase3ZKUProofMessage(from *PartyID, ZKUProof *schnorrZK.ZKProof) *KGPhase3ZKUProofMessage {
	return &KGPhase3ZKUProofMessage{
		KGMessageMetadata: &KGMessageMetadata{
			from:      from,
			stateName: "KGPhase3ZKUProofMessage",
		},
		ZKUProof: ZKUProof,
	}
}
