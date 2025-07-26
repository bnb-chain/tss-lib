// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/sha512"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/mt-solt/tss-lib/common"
	"github.com/pkg/errors"

	"github.com/mt-solt/tss-lib/crypto"
	"github.com/mt-solt/tss-lib/crypto/commitments"
	"github.com/mt-solt/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOK()

	// 1. init R
	riBytes := bigIntToEncodedBytes(round.temp.ri)
	riScalar, err := edwards25519.NewScalar().SetCanonicalBytes(riBytes[:])
	if err != nil {
		return round.WrapError(errors.Wrap(err, "SetCanonicalBytes(ri)"))
	}
	R := new(edwards25519.Point).ScalarBaseMult(riScalar)

	// 2-6. compute R
	i := round.Params().PartyID().Index
	for j, Pj := range round.Params().Parties().IDs() {
		if j == i {
			continue
		}

		ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*SignRound2Message)
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
		ok, coordinates := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		if len(coordinates) != 2 {
			return round.WrapError(errors.New("length of de-commitment should be 2"))
		}

		Rj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
		Rj = Rj.EightInvEight()
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}
		proof, err := r2msg.UnmarshalZKProof(round.Params().EC())
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Rj proof"), Pj)
		}
		ok = proof.Verify(ContextJ, Rj)
		if !ok {
			return round.WrapError(errors.New("failed to prove Rj"), Pj)
		}

		extendedRj := ecPointToExtendedElement(round.Params().EC(), Rj.X(), Rj.Y(), round.Params().Rand())
		R.Add(R, extendedRj)
	}

	// 7. compute lambda
	var encodedR [32]byte
	copy(encodedR[:], R.Bytes())
	encodedPubKey := ecPointToEncodedBytes(round.key.EDDSAPub.X(), round.key.EDDSAPub.Y())

	// h = hash512(k || A || M)
	h := sha512.New()
	h.Reset()
	h.Write(encodedR[:])
	h.Write(encodedPubKey[:])
	if round.temp.fullBytesLen == 0 {
		h.Write(round.temp.m.Bytes())
	} else {
		var mBytes = make([]byte, round.temp.fullBytesLen)
		round.temp.m.FillBytes(mBytes)
		h.Write(mBytes)
	}

	var lambda [64]byte
	h.Sum(lambda[:0])
	lambdaScalar, _ := edwards25519.NewScalar().SetUniformBytes(lambda[:])

	// 8. compute si
	wiScalar, err := edwards25519.NewScalar().SetCanonicalBytes(bigIntToEncodedBytes(round.temp.wi)[:])
	if err != nil {
		return round.WrapError(errors.Wrap(err, "SetCanonicalBytes(wi)"))
	}
	localS := edwards25519.NewScalar().Multiply(lambdaScalar, wiScalar)
	localS.Add(localS, riScalar)

	// 9. store r3 message pieces
	localSBytes := localS.Bytes()
	var localSArr [32]byte
	copy(localSArr[:], localSBytes)
	round.temp.si = &localSArr
	round.temp.r = encodedBytesToBigInt(&encodedR)

	// 10. broadcast si to other parties
	r3msg := NewSignRound3Message(round.Params().PartyID(), encodedBytesToBigInt(&localSArr))
	round.temp.signRound3Messages[round.Params().PartyID().Index] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
