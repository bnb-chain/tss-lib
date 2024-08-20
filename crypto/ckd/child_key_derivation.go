// Copyright © Swingby

package ckd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

type ExtendedKey struct {
	ecdsa.PublicKey
	Depth      uint8
	ChildIndex uint32
	ChainCode  []byte // 32 bytes
	ParentFP   []byte // parent fingerprint
	Version    []byte
}

// For more information about child key derivation see https://github.com/binance-chain/tss-lib/issues/104
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki .
// The functions below do not implement the full BIP-32 specification. As mentioned in the Jira ticket above,
// we only use non-hardened derived keys.

const (

	// HardenedKeyStart hardened key starts.
	HardenedKeyStart = 0x80000000 // 2^31

	// max Depth
	maxDepth = 1<<8 - 1

	PubKeyBytesLenCompressed = 33

	pubKeyCompressed byte = 0x2

	serializedKeyLen = 78

	// MinSeedBytes is the minimum number of bytes allowed for a seed to
	// a master node.
	MinSeedBytes = 16 // 128 bits

	// MaxSeedBytes is the maximum number of bytes allowed for a seed to
	// a master node.
	MaxSeedBytes = 64 // 512 bits
)

// Extended public key serialization, defined in BIP32
func (k *ExtendedKey) String() string {
	// version(4) || depth(1) || parentFP (4) || childinde(4) || chaincode (32) || key(33) || checksum(4)
	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.ChildIndex)

	serializedBytes := make([]byte, 0, serializedKeyLen+4)
	serializedBytes = append(serializedBytes, k.Version...)
	serializedBytes = append(serializedBytes, k.Depth)
	serializedBytes = append(serializedBytes, k.ParentFP...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, k.ChainCode...)
	pubKeyBytes := serializeCompressed(k.PublicKey.X, k.PublicKey.Y)
	serializedBytes = append(serializedBytes, pubKeyBytes...)

	checkSum := doubleHashB(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return base58.Encode(serializedBytes)
}

// NewExtendedKeyFromString returns a new extended key from a base58-encoded extended key
func NewExtendedKeyFromString(key string, curve elliptic.Curve) (*ExtendedKey, error) {
	// version(4) || depth(1) || parentFP (4) || childinde(4) || chaincode (32) || key(33) || checksum(4)

	decoded := base58.Decode(key)
	if len(decoded) != serializedKeyLen+4 {
		return nil, errors.New("invalid extended key")
	}

	// Split the payload and checksum up and ensure the checksum matches.
	payload := decoded[:len(decoded)-4]
	checkSum := decoded[len(decoded)-4:]
	expectedCheckSum := doubleHashB(payload)[:4]
	if !bytes.Equal(checkSum, expectedCheckSum) {
		return nil, errors.New("invalid extended key")
	}

	// Deserialize each of the payload fields.
	version := payload[:4]
	depth := payload[4:5][0]
	parentFP := payload[5:9]
	childNum := binary.BigEndian.Uint32(payload[9:13])
	chainCode := payload[13:45]
	keyData := payload[45:78]

	var pubKey ecdsa.PublicKey

	if c, ok := curve.(*btcec.KoblitzCurve); ok {
		pk, err := btcec.ParsePubKey(keyData)
		if err != nil {
			return nil, err
		}
		pubKey = ecdsa.PublicKey{
			Curve: c,
			X:     pk.X(),
			Y:     pk.Y(),
		}
	} else {
		px, py := elliptic.Unmarshal(curve, keyData)
		pubKey = ecdsa.PublicKey{
			Curve: curve,
			X:     px,
			Y:     py,
		}
	}

	return &ExtendedKey{
		PublicKey:  pubKey,
		Depth:      depth,
		ChildIndex: childNum,
		ChainCode:  chainCode,
		ParentFP:   parentFP,
		Version:    version,
	}, nil
}

func doubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

func hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

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

func DeriveChildKeyFromHierarchy(indicesHierarchy []uint32, pk *ExtendedKey, mod *big.Int, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	var k = pk
	var err error
	var childKey *ExtendedKey
	mod_ := common.ModInt(mod)
	ilNum := big.NewInt(0)
	for index := range indicesHierarchy {
		ilNumOld := ilNum
		ilNum, childKey, err = DeriveChildKey(indicesHierarchy[index], k, curve)
		if err != nil {
			return nil, nil, err
		}
		k = childKey
		ilNum = mod_.Add(ilNum, ilNumOld)
	}
	return ilNum, k, nil
}

// DeriveChildKey Derive a child key from the given parent key. The function returns "IL" ("I left"), per BIP-32 spec. It also
// returns the derived child key.
func DeriveChildKey(index uint32, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	cryptoPk, err := crypto.NewECPoint(curve, pk.X, pk.Y)
	if err != nil {
		common.Logger.Error("error getting pubkey from extendedkey")
		return nil, nil, err
	}

	pkPublicKeyBytes := serializeCompressed(pk.X, pk.Y)

	data := make([]byte, 37)
	copy(data, pkPublicKeyBytes)
	binary.BigEndian.PutUint32(data[33:], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)

	if ilNum.Cmp(curve.Params().N) >= 0 || ilNum.Sign() == 0 {
		// falling outside of the valid range for curve private keys
		err = errors.New("invalid derived key")
		common.Logger.Error("error deriving child key")
		return nil, nil, err
	}

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		err = errors.New("invalid child")
		common.Logger.Error("error invalid child")
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
		ParentFP:   hash160(pkPublicKeyBytes)[:4],
		Version:    pk.Version,
	}
	return ilNum, childPk, nil
}
