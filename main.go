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
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/bnb-chain/tss-lib/v2/mpc"
	"github.com/bnb-chain/tss-lib/v2/mpc/ecdsa"
	"github.com/bnb-chain/tss-lib/v2/mpc/eddsa"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

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

var logLevel = "info"

func main() {
	// signTest()
	// return

	algo := os.Args[1]
	step := os.Args[2]
	groupId := os.Args[3]
	totalCount, _ := strconv.ParseInt(os.Args[4], 10, 32)
	threshold, _ := strconv.ParseInt(os.Args[5], 10, 32)
	index, _ := strconv.ParseInt(os.Args[6], 10, 32)

	// if err := log.SetLogLevel("tss-lib", logLevel); err != nil {
	// 	panic(err)
	// }

	// fmt.Printf("Test Args Count[%d]\n", len(os.Args))
	// for idx, curArg := range os.Args {
	// 	fmt.Printf("  [%d][%s]\n", idx, curArg)
	// }

	if "KEYGEN" == step {
		fmt.Printf("===========%s[%d-of-%d][%d] Start [%s]===========\n", algo, threshold, totalCount, index, step)
		var saveFilePath string
		if "EC" == algo {
			saveFilePath = ecdsa.KeygenProc(groupId, int(totalCount), int(threshold), int(index))
		} else if "ED" == algo {
			saveFilePath = eddsa.KeygenProc(groupId, int(totalCount), int(threshold), int(index))
		} else {
			panic(fmt.Sprintf("algo [%s] is not support\n", algo))
		}

		out, _ := ioutil.ReadFile(saveFilePath)
		fmt.Printf("keygen result [%s]\n%s\n", saveFilePath, string(out))
		fmt.Printf("===========%s[%d-of-%d][%d] End [%s]===========\n", algo, threshold, totalCount, index, step)
	} else if "SIGNING" == step {
		fmt.Printf("===========%s[%d-of-%d][%d][%s] Start [%s]===========\n", algo, threshold, totalCount, index, os.Args[7], step)
		var signInfo *mpc.FSLMPCSignInfo
		var signerIndexes []int
		for _, signerIndex := range strings.Split(os.Args[7], ",") {
			curIndex, _ := strconv.ParseInt(signerIndex, 10, 32)
			signerIndexes = append(signerIndexes, int(curIndex))
		}
		hexSignMessage := hex.EncodeToString([]byte(os.Args[8]))
		if "EC" == algo {
			signInfo = ecdsa.SigningProc(groupId, int(totalCount), int(threshold), int(index), signerIndexes, hexSignMessage)
		} else if "ED" == algo {
			signInfo = eddsa.SigningProc(groupId, int(totalCount), int(threshold), int(index), signerIndexes, hexSignMessage)
		} else {
			panic(fmt.Sprintf("algo [%s] is not support\n", algo))
		}

		out, _ := json.MarshalIndent(signInfo, "", "  ")
		fmt.Printf("signing result [%s]\n", string(out))
		fmt.Printf("===========%s[%d-of-%d][%d][%s] End [%s]===========\n", algo, threshold, totalCount, index, os.Args[7], step)
	} else {
		panic(fmt.Sprintf("step [%s] is not support\n", step))
	}
}
