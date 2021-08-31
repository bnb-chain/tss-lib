// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message)(nil),
	}
)

// ----- //

func NewSignRound1Message(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m.Commitment != nil &&
		common.NonEmptyBytes(m.GetCommitment())
}

func (m *SignRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewSignRound2Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *schnorr.ZKProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &SignRound2Message{
		DeCommitment: dcBzs,
		ProofAlphaX:  proof.Alpha.X().Bytes(),
		ProofAlphaY:  proof.Alpha.Y().Bytes(),
		ProofT:       proof.T.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 3) &&
		common.NonEmptyBytes(m.ProofAlphaX) &&
		common.NonEmptyBytes(m.ProofAlphaY) &&
		common.NonEmptyBytes(m.ProofT)
}

func (m *SignRound2Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *SignRound2Message) UnmarshalZKProof() (*schnorr.ZKProof, error) {
	point, err := crypto.NewECPoint(
		tss.EC(),
		new(big.Int).SetBytes(m.GetProofAlphaX()),
		new(big.Int).SetBytes(m.GetProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &schnorr.ZKProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetProofT()),
	}, nil
}

// ----- //

func NewSignRound3Message(
	from *tss.PartyID,
	si *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message{
		S: si.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.S)
}

func (m *SignRound3Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.S)
}
