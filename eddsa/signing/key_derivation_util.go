// Copyright © 2021 Swingby

package signing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/ckd"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
)

func UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta *big.Int, keys []keygen.LocalPartySaveData, extendedChildPk *crypto.ECPoint, ec elliptic.Curve) error {
	var err error
	gDelta := crypto.ScalarBaseMult(ec, keyDerivationDelta)
	for k := range keys {
		keys[k].EDDSAPub = extendedChildPk
		// Suppose X_j has shamir shares X_j0,     X_j1,     ..., X_jn
		// So X_j + D has shamir shares  X_j0 + D, X_j1 + D, ..., X_jn + D
		for j := range keys[k].BigXj {
			keys[k].BigXj[j], err = keys[k].BigXj[j].Add(gDelta)
			if err != nil {
				common.Logger.Errorf("error in delta operation")
				return err
			}
		}
	}
	return nil
}

func derivingPubkeyFromPath(masterPub *crypto.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  masterPub,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    []byte{0x02, 0xe8, 0xda, 0x54},
	}

	return ckd.DeriveChildKeyFromHierarchy(path, extendedParentPk, ec.Params().N, ec)
}
