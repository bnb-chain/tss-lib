// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	LocalPreParams struct {
		PaillierSK        *paillier.PrivateKey // ski
		NTildei, H1i, H2i *big.Int             // n-tilde, h1, h2
	}

	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalPreParams
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// n-tilde, h1, h2 for range proofs
		NTildej, H1j, H2j []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj       []*crypto.ECPoint     // Xj
		PaillierPKs []*paillier.PublicKey // pkj

		// used for test assertions (may be discarded)
		ECDSAPub *crypto.ECPoint // y
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.NTildej = make([]*big.Int, partyCount)
	saveData.H1j, saveData.H2j = make([]*big.Int, partyCount), make([]*big.Int, partyCount)
	saveData.BigXj = make([]*crypto.ECPoint, partyCount)
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	return
}

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil && preParams.NTildei != nil && preParams.H1i != nil && preParams.H2i != nil
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(result LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(result.Ks))
	for j, kj := range result.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newSaveData := NewLocalPartySaveData(sortedIDs.Len())
	newSaveData.LocalPreParams = result.LocalPreParams
	newSaveData.LocalSecrets = result.LocalSecrets
	newSaveData.ECDSAPub = result.ECDSAPub
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			common.Logger.Warning("BuildLocalSaveDataSubset: unable to find a signer party in the local save data", id)
		}
		newSaveData.Ks[j] = result.Ks[savedIdx]
		newSaveData.NTildej[j] = result.NTildej[savedIdx]
		newSaveData.H1j[j] = result.H1j[savedIdx]
		newSaveData.H2j[j] = result.H2j[savedIdx]
		newSaveData.BigXj[j] = result.BigXj[savedIdx]
		newSaveData.PaillierPKs[j] = result.PaillierPKs[savedIdx]
	}
	return newSaveData
}
