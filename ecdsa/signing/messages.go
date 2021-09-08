// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkpaffg "github.com/binance-chain/tss-lib/crypto/zkp/affg"
	zkpenc "github.com/binance-chain/tss-lib/crypto/zkp/enc"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
    // Ensure that signing messages implement ValidateBasic
    _ = []tss.MessageContent{
        (*SignRound1Message)(nil),
        (*SignRound2Message)(nil),
        (*SignRound3Message)(nil),
        (*SignRound4Message)(nil),
    }
)

// ----- //

func NewSignRound1Message(
    to, from *tss.PartyID,
    K *big.Int,
    G *big.Int,
    EncProof *zkpenc.ProofEnc,
) tss.ParsedMessage {
    meta := tss.MessageRouting{
        From:        from,
        To:          []*tss.PartyID{to},
        IsBroadcast: false,
    }
    pfBz := EncProof.Bytes()
    content := &SignRound1Message{
        K:				 K.Bytes(),
        G:               G.Bytes(),
        EncProof: 		 pfBz[:],
    }
    msg := tss.NewMessageWrapper(meta, content)
    return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
    return m != nil &&
        common.NonEmptyBytes(m.K) &&
        common.NonEmptyBytes(m.G) &&
        common.NonEmptyMultiBytes(m.EncProof, zkpenc.ProofEncBytesParts)
}

func (m *SignRound1Message) UnmarshalK() *big.Int {
    return new(big.Int).SetBytes(m.GetK())
}

func (m *SignRound1Message) UnmarshalG() *big.Int {
    return new(big.Int).SetBytes(m.GetG())
}

func (m *SignRound1Message) UnmarshalEncProof() (*zkpenc.ProofEnc, error) {
    return zkpenc.NewProofFromBytes(m.GetEncProof())
}

// ----- //

func NewSignRound2Message(
    to, from *tss.PartyID,
    BigGammaShare *crypto.ECPoint,
    DjiDelta *big.Int,
    FjiDelta *big.Int,
    DjiChi *big.Int,
    FjiChi *big.Int,
    AffgProofDelta *zkpaffg.ProofAffg,
    AffgProofChi *zkpaffg.ProofAffg,
    LogstarProof *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
    meta := tss.MessageRouting{
        From:        from,
        To:          []*tss.PartyID{to},
        IsBroadcast: false,
    }
    BigGammaBytes, _ := BigGammaShare.MarshalJSON()
    AffgDeltaBz := AffgProofDelta.Bytes()
    AffgChiBz := AffgProofChi.Bytes()
    LogstarBz := LogstarProof.Bytes()
    content := &SignRound2Message{
        BigGammaShare: 	BigGammaBytes,
        DjiDelta:       DjiDelta.Bytes(),
        FjiDelta:       FjiDelta.Bytes(),
        DjiChi:         DjiChi.Bytes(),
        FjiChi:         FjiChi.Bytes(),
        AffgProofDelta: AffgDeltaBz[:],
        AffgProofChi:   AffgChiBz[:],
        LogstarProof:   LogstarBz[:],
    }
    msg := tss.NewMessageWrapper(meta, content)
    return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
    return m != nil &&
        common.NonEmptyBytes(m.BigGammaShare) &&
        common.NonEmptyBytes(m.DjiDelta) &&
        common.NonEmptyBytes(m.FjiDelta) &&
        common.NonEmptyBytes(m.DjiChi) &&
        common.NonEmptyBytes(m.FjiChi) &&
        common.NonEmptyMultiBytes(m.AffgProofDelta, zkpaffg.ProofAffgBytesParts) &&
        common.NonEmptyMultiBytes(m.AffgProofChi, zkpaffg.ProofAffgBytesParts) &&
        common.NonEmptyMultiBytes(m.LogstarProof, zkplogstar.ProofLogstarBytesParts)
}

func (m *SignRound2Message) UnmarshalBigGammaShare(ec elliptic.Curve) *crypto.ECPoint {
    point := crypto.NewECPointNoCurveCheck(ec, big.NewInt(0), big.NewInt(0))
    point.UnmarshalJSON(m.GetBigGammaShare())
    return point
}

func (m *SignRound2Message) UnmarshalDjiDelta() *big.Int {
    return new(big.Int).SetBytes(m.GetDjiDelta())
}

func (m *SignRound2Message) UnmarshalFjiDelta() *big.Int {
    return new(big.Int).SetBytes(m.GetFjiDelta())
}

func (m *SignRound2Message) UnmarshalDjiChi() *big.Int {
    return new(big.Int).SetBytes(m.GetDjiChi())
}

func (m *SignRound2Message) UnmarshalFjiChi() *big.Int {
    return new(big.Int).SetBytes(m.GetFjiChi())
}

func (m *SignRound2Message) UnmarshalAffgProofDelta(ec elliptic.Curve) (*zkpaffg.ProofAffg, error) {
    return zkpaffg.NewProofFromBytes(ec, m.GetAffgProofDelta())
}

func (m *SignRound2Message) UnmarshalAffgProofChi(ec elliptic.Curve) (*zkpaffg.ProofAffg, error) {
    return zkpaffg.NewProofFromBytes(ec, m.GetAffgProofChi())
}

func (m *SignRound2Message) UnmarshalLogstarProof(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
    return zkplogstar.NewProofFromBytes(ec, m.GetLogstarProof())
}

// ----- //

func NewSignRound3Message(
    to, from *tss.PartyID,
    DeltaShare *big.Int,
    BigDeltaShare *crypto.ECPoint,
    ProofLogstar *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
    meta := tss.MessageRouting{
        From:        from,
		To:          []*tss.PartyID{to},
        IsBroadcast: false,
    }
    BigDeltaShareDmp, _ := BigDeltaShare.MarshalJSON()
	// BDBz := [2][]byte{BigDeltaShare.X().Bytes(), BigDeltaShare.Y().Bytes()} //TODO
    ProofBz := ProofLogstar.Bytes()
    content := &SignRound3Message{
        DeltaShare: DeltaShare.Bytes(),
        BigDeltaShare: BigDeltaShareDmp,
        ProofLogstar: ProofBz[:],
    }
    msg := tss.NewMessageWrapper(meta, content)
    return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
    return m != nil &&
        common.NonEmptyBytes(m.DeltaShare) &&
        common.NonEmptyBytes(m.BigDeltaShare) &&
        common.NonEmptyMultiBytes(m.ProofLogstar, zkplogstar.ProofLogstarBytesParts)
}

func (m *SignRound3Message) UnmarshalDeltaShare() *big.Int {
    return new(big.Int).SetBytes(m.GetDeltaShare())
}

func (m *SignRound3Message) UnmarshalBigDeltaShare(ec elliptic.Curve) *crypto.ECPoint {
    point := crypto.NewECPointNoCurveCheck(ec, big.NewInt(0), big.NewInt(0))
    point.UnmarshalJSON(m.GetBigDeltaShare())
    return point
}

func (m *SignRound3Message) UnmarshalProofLogstar(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
    return zkplogstar.NewProofFromBytes(ec, m.GetProofLogstar())
}

// ----- //

func NewSignRound4Message(
    from *tss.PartyID,
    SigmaShare *big.Int,
) tss.ParsedMessage {
    meta := tss.MessageRouting{
        From:        from,
        IsBroadcast: true,
    }
    content := &SignRound4Message{
        SigmaShare: SigmaShare.Bytes(),
    }
    msg := tss.NewMessageWrapper(meta, content)
    return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic() bool {
    return m != nil &&
        common.NonEmptyBytes(m.SigmaShare)
}

func (m *SignRound4Message) UnmarshalSigmaShare() *big.Int {
    return new(big.Int).SetBytes(m.GetSigmaShare())
}
