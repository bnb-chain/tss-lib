// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/bnb-chain/tss-lib/v2/mpc"
	"github.com/bnb-chain/tss-lib/v2/mpc/ecdsa"
	"github.com/bnb-chain/tss-lib/v2/mpc/eddsa"
)

var logLevel = "info"

func signTest() {
	secretBytes, _ := hex.DecodeString("d37ab481909f944db8a9a4c6bfbb76b4f28e0421dd476da03dcfe9775ec5ee37")
	{
		pri, pub := edwards.PrivKeyFromSecret(secretBytes)

		fmt.Printf("pri.SerializeSecret : [%s]\n", hex.EncodeToString(pri.SerializeSecret()))
		fmt.Printf("pri.Serialize       : [%s]\n", hex.EncodeToString(pri.Serialize()))
		fmt.Printf("pri.GetD            : [%s]\n", hex.EncodeToString(pri.GetD().Bytes()))

		fmt.Printf("pub.GetX                  : [%s]\n", hex.EncodeToString(pub.GetX().Bytes()))
		fmt.Printf("pub.GetY                  : [%s]\n", hex.EncodeToString(pub.GetY().Bytes()))
		fmt.Printf("pub.Serialize             : [%s]\n", hex.EncodeToString(pub.Serialize()))
		fmt.Printf("pub.SerializeCompressed   : [%s]\n", hex.EncodeToString(pub.SerializeCompressed()))
		fmt.Printf("pub.SerializeUncompressed : [%s]\n", hex.EncodeToString(pub.SerializeUncompressed()))

		var strOri = "string"
		r, s, _ := edwards.Sign(pri, []byte(strOri))
		brr, brs := mpc.Reverse(r.Bytes()), mpc.Reverse(s.Bytes())
		fmt.Printf("sing.R                   : [%s]\n", hex.EncodeToString(brr))
		fmt.Printf("sign.S                   : [%s]\n", hex.EncodeToString(brs))

		br, bs := mpc.Reverse(brr), mpc.Reverse(brs)
		if true == edwards.Verify(pub, []byte(strOri), new(big.Int).SetBytes(br), new(big.Int).SetBytes(bs)) {
			fmt.Printf("verify success\n")
		} else {
			fmt.Printf("verify failed\n")
		}
	}

	// priBytes, _ := hex.DecodeString("d37ab481909f944db8a9a4c6bfbb76b4f28e0421dd476da03dcfe9775ec5ee37fb1a7ffd378a157d59033007ac3abb9649c89c4c24ff0ce420477b06e430fd62")
	// {
	//	pri, pub := edwards.PrivKeyFromBytes(priBytes)
	//
	//	fmt.Printf("pri.SerializeSecret : [%s]\n", hex.EncodeToString(pri.SerializeSecret()))
	//	fmt.Printf("pri.Serialize       : [%s]\n", hex.EncodeToString(pri.Serialize()))
	//	fmt.Printf("pri.GetD            : [%s]\n", hex.EncodeToString(pri.GetD().Bytes()))
	//
	//	fmt.Printf("pub.GetX                  : [%s]\n", hex.EncodeToString(pub.GetX().Bytes()))
	//	fmt.Printf("pub.GetY                  : [%s]\n", hex.EncodeToString(pub.GetY().Bytes()))
	//	fmt.Printf("pub.Serialize             : [%s]\n", hex.EncodeToString(pub.Serialize()))
	//	fmt.Printf("pub.SerializeCompressed   : [%s]\n", hex.EncodeToString(pub.SerializeCompressed()))
	//	fmt.Printf("pub.SerializeUncompressed : [%s]\n", hex.EncodeToString(pub.SerializeUncompressed()))
	// }
}

func main() {
	// signTest()
	// return

	var totalCount = 3
	var threshold = 2
	var out []byte

	// if err := log.SetLogLevel("tss-lib", logLevel); err != nil {
	// 	panic(err)
	// }

	strOri := "string"
	hexOri := hex.EncodeToString([]byte(strOri))
	hexHash := mpc.MakeHashFromString(hexOri)
	bHash, _ := hex.DecodeString(hexHash)
	// hexHash1 = mpc.MakeHashFromBigInt(biOri)

	{
		savedIndexes, masterPub := ecdsa.KeygenProc(threshold, totalCount)
		fmt.Printf("keyGen index [%v]\n", savedIndexes)
		out, _ = json.MarshalIndent(masterPub, "", "  ")
		fmt.Printf("keygen result [%s]\n", string(out))

		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(savedIndexes), func(i, j int) { savedIndexes[i], savedIndexes[j] = savedIndexes[j], savedIndexes[i] })

		var signIndexes = savedIndexes[:threshold]
		fmt.Printf("signing keys index [%v]\n", signIndexes)

		sigInfo := ecdsa.SigningProc(threshold, totalCount, signIndexes, bHash)
		out, _ = json.MarshalIndent(sigInfo, "", "  ")
		fmt.Printf("signing result [%s]\n", string(out))
	}

	{
		savedIndexes, masterPub := eddsa.KeygenProc(threshold, totalCount)
		fmt.Printf("keyGen keys[%s] index [%v]\n", masterPub, savedIndexes)

		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(savedIndexes), func(i, j int) { savedIndexes[i], savedIndexes[j] = savedIndexes[j], savedIndexes[i] })

		var signIndexes = savedIndexes[:threshold]
		fmt.Printf("signing keys index [%v]\n", signIndexes)

		sigInfo := eddsa.SigningProc(threshold, totalCount, signIndexes, bHash)
		out, _ = json.MarshalIndent(sigInfo, "", "  ")
		fmt.Printf("signing result [%s]\n", string(out))
	}

}
