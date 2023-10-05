// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package ecdsa

import (
	"crypto/ecdsa"
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"

	"github.com/bnb-chain/tss-lib/v2/mpc"
)

func LoadKey(algo string, groupId string, totalCount int, threshold int, index int) (*keygen.LocalPartySaveData, error) {
	keyFilePath := mpc.GetKeyFilePath(algo, groupId, totalCount, threshold, index)
	bz, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}
	var key keygen.LocalPartySaveData
	if err = json.Unmarshal(bz, &key); err != nil {
		return nil, err
	}
	for _, kbxj := range key.BigXj {
		kbxj.SetCurve(tss.EC())
	}
	key.ECDSAPub.SetCurve(tss.EC())
	return &key, nil
}

func GetPublicKeyFromSaveData(saveData *keygen.LocalPartySaveData) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     saveData.ECDSAPub.X(),
		Y:     saveData.ECDSAPub.Y(),
	}
}

func GetMPCPubFromSaveData(saveData *keygen.LocalPartySaveData) *mpc.FSLMPCPublicKey {
	publicKey := GetPublicKeyFromSaveData(saveData)
	hexPubX := publicKey.X.Text(16)
	for 64 > len(hexPubX) {
		hexPubX = "0" + hexPubX
	}

	hexPubY := publicKey.Y.Text(16)
	for 64 > len(hexPubY) {
		hexPubY = "0" + hexPubY
	}

	return &mpc.FSLMPCPublicKey{
		Curve:  tss.EC().Params().Name,
		X:      hexPubX,
		Y:      hexPubY,
		Encode: "04" + hexPubX + hexPubY,
	}
}

func SaveKey(algo string, groupId string, totalCount int, threshold int, savedIndex int, data *keygen.LocalPartySaveData) string {
	keyFilePath := mpc.GetKeyFilePath(algo, groupId, totalCount, threshold, savedIndex)
	fd, err := os.OpenFile(keyFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err.Error())
	}

	bz, err := json.MarshalIndent(&data, "", "  ")
	if err != nil {
		panic(err.Error())
	}

	_, err = fd.Write(bz)
	if err != nil {
		panic(err.Error())
	}

	return keyFilePath
}
