// Copyright © Swingby

package ckd

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

type ExtendedKey struct {
	ecdsa.PublicKey
	Depth      byte
	ChildIndex uint32
	ChainCode  []byte // 32 bytes
}

// For more information about child key derivation see https://github.com/binance-chain/tss-lib/issues/104
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki .
// The functions below do not implement the full BIP-32 specification. As mentioned in the Jira ticket above,
// we only use non-hardened derived keys.

const (

	// HardenedKeyStart hardened key starts.
	HardenedKeyStart = 0x80000000 // 2^31

	// max Depth
	maxDepth = 0xFF

	PubKeyBytesLenCompressed = 33

	pubKeyCompressed byte = 0x2
)

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// PaddedAppend append src to dst, if less than size padding 0 at start
func paddedAppend(dst []byte, srcPaddedSize int, src []byte) []byte {
	return append(dst, paddedBytes(srcPaddedSize, src)...)
}

// PaddedBytes padding byte array to size length
func paddedBytes(size int, src []byte) []byte {
	offset := size - len(src)
	tmp := src
	if offset > 0 {
		tmp = make([]byte, size)
		copy(tmp[offset:], src)
	}
	return tmp
}

// SerializeCompressed serializes a public key 33-byte compressed format
func serializeCompressed(publicKeyX *big.Int, publicKeyY *big.Int) []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubKeyCompressed
	if isOdd(publicKeyY) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(b, 32, publicKeyX.Bytes())
}

func DeriveChildKeyFromHierarchy(indicesHierarchy []uint32, pk *ExtendedKey, mod *big.Int) (*big.Int, *ExtendedKey, error) {
	var k = pk
	var err error
	var childKey *ExtendedKey
	mod_ := common.ModInt(mod)
	ilNum := big.NewInt(0)
	for index := range indicesHierarchy {
		ilNumOld := ilNum
		ilNum, childKey, err = DeriveChildKey(indicesHierarchy[index], k)
		if err != nil {
			return nil, nil, err
		}
		k = childKey
		ilNum = mod_.Add(ilNum, ilNumOld)
	}
	return ilNum, k, nil
}

// Derive a child key from the given parent key. The function returns "IL" ("I left"), per BIP-32 spec. It also
// returns the derived child key.
func DeriveChildKey(index uint32, pk *ExtendedKey) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	cryptoPk, err := crypto.NewECPoint(tss.EC(), pk.X, pk.Y)

	data := make([]byte, 37)
	copy(data, serializeCompressed(pk.X, pk.Y))
	binary.BigEndian.PutUint32(data[33:], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)

	if ilNum.Cmp(tss.EC().Params().N) >= 0  || ilNum.Sign() == 0 {
		// falling outside of the valid range for curve private keys
		err = errors.New("invalid derived key")
		common.Logger.Error("error deriving child key")
		return nil, nil, err
	}

	deltaG := crypto.ScalarBaseMult(tss.EC(), ilNum)
	if err != nil {
		common.Logger.Error("error computing delta G")
		return nil, nil, err
	}
	childCryptoPk, err := cryptoPk.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}
	childPk := &ExtendedKey{
		PublicKey:  *childCryptoPk.ToECDSAPubKey(),
		Depth:      pk.Depth + 1,
		ChildIndex: index,
		ChainCode:  childChainCode,
	}
	return ilNum, childPk, nil
}
