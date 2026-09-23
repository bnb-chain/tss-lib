// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	cmt "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-resharing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*DGRound1Message)(nil),
		(*DGRound2Message)(nil),
		(*DGRound3Message1)(nil),
		(*DGRound3Message2)(nil),
		(*DGRound4Message)(nil),
	}
)

// ----- //

func NewDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	eddsaPub *crypto.ECPoint,
	vct cmt.HashCommitment,
	ssid []byte,
	sessionNonceHash []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	content := &DGRound1Message{
		EddsaPubX:   eddsaPub.X().Bytes(),
		EddsaPubY:   eddsaPub.Y().Bytes(),
		VCommitment: vct.Bytes(),
		Ssid:        ssid,
		// See the proto comment: the new committee cannot recompute `Ssid`, so
		// this is the one value in this message it can check against something
		// of its own.
		SessionNonceHash: sessionNonceHash,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// sessionDigestMaxBytes bounds the two SHA512_256-derived fields below. Both are
// produced as common.SHA512_256i(...).Bytes(), a 32-byte digest with leading
// zeroes dropped, so 32 is the exact upper bound a conforming sender can reach
// and not a guess. It matters because neither field had one: the ssid is adopted
// into round.temp.ssid, so its declared length is a length this party carries.
const sessionDigestMaxBytes = 32

// ValidateBasic requires SessionNonceHash. An absent hash is exactly what a
// transcript recorded before this field existed carries, and it must not be
// laundered into "nothing to compare" by round 2. Ssid is deliberately not
// required to be non-empty here: round 2 tests it for length itself, so that an
// empty declaration is rejected with an ssid-specific error that names the
// sender rather than being dropped by the message layer with no attribution.
// Both fields are bounded from above regardless.
func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.EddsaPubX) &&
		common.NonEmptyBytes(m.EddsaPubY) &&
		common.NonEmptyBytes(m.VCommitment) &&
		common.NonEmptyBytes(m.SessionNonceHash) &&
		len(m.SessionNonceHash) <= sessionDigestMaxBytes &&
		len(m.Ssid) <= sessionDigestMaxBytes
}

func (m *DGRound1Message) UnmarshalSSID() []byte {
	return m.GetSsid()
}

func (m *DGRound1Message) UnmarshalSessionNonceHash() []byte {
	return m.GetSessionNonceHash()
}

func (m *DGRound1Message) UnmarshalEDDSAPub(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.EddsaPubX),
		new(big.Int).SetBytes(m.EddsaPubY))
}

func (m *DGRound1Message) UnmarshalVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetVCommitment())
}

// ----- //

func NewDGRound2Message(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: true,
	}
	content := &DGRound2Message{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound2Message) ValidateBasic() bool {
	return true
}

// ----- //

func NewDGRound3Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	content := &DGRound3Message1{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Share)
}

// ----- //

func NewDGRound3Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
	vdct cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	content := &DGRound3Message2{
		VDecommitment: vDctBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.VDecommitment)
}

func (m *DGRound3Message2) UnmarshalVDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetVDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewDGRound4Message(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &DGRound4Message{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message) ValidateBasic() bool {
	return true
}
