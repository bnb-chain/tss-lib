// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

type (
	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj []*crypto.ECPoint // Xj

		// used for test assertions (may be discarded)
		EDDSAPub *crypto.ECPoint // y
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.BigXj = make([]*crypto.ECPoint, partyCount)
	return
}

// copyLocalSecrets returns a LocalSecrets whose *big.Int fields are fresh, so the
// result shares no mutable state with `s`. A nil field stays nil rather than
// becoming a zero-valued big.Int: callers distinguish "absent" from "zero".
func copyLocalSecrets(s LocalSecrets) LocalSecrets {
	out := LocalSecrets{}
	if s.Xi != nil {
		out.Xi = new(big.Int).Set(s.Xi)
	}
	if s.ShareID != nil {
		out.ShareID = new(big.Int).Set(s.ShareID)
	}
	return out
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
//
// LocalSecrets is DEEP-COPIED, not assigned. Its fields are *big.Int, so a plain
// struct assignment would leave the returned value sharing the caller's numbers,
// and anything this library writes through them would reach the caller's own save
// data. This is load-bearing: see doc/maintenance-invariants.md.
//
// LocalSecrets is the ONLY thing copied. Everything else in the returned value is
// shared with the caller: EDDSAPub is the caller's pointer, and while Ks and BigXj
// are freshly allocated slices, the elements they hold are the caller's pointers.
// None of that is secret material, which is why only LocalSecrets is copied. If
// this library ever writes through any of it, extend the copy first.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalSecrets = copyLocalSecrets(sourceData.LocalSecrets)
	newData.EDDSAPub = sourceData.EDDSAPub
	for j, id := range sortedIDs {
		// `id.Key` is a PROMOTED field: reading it dereferences the embedded
		// *MessageWrapper_PartyID, which is nil in the PartyID shapes that
		// encoding/json and a shallow copy produce. Attribute that here instead
		// of faulting one expression later with no message: this function has no
		// return channel, and an unresolvable roster entry already panics with a
		// named message just below, so a roster entry that cannot be read at all
		// belongs in the same place.
		if id == nil || id.MessageWrapper_PartyID == nil {
			panic("BuildLocalSaveDataSubset: a party in the given roster has no PartyID content")
		}
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			panic("BuildLocalSaveDataSubset: unable to find a signer party in the local save data")
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.BigXj[j] = sourceData.BigXj[savedIdx]
	}
	return newData
}
