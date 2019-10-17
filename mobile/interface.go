// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Entry points for gomobile bindings

package mobile

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	AlgorithmECDSA = iota
	ProtocolKeygen = iota
	ProtocolSigning
	ProtocolReSharing
)

type (
	// LocalParty sessions are kept in Go land
	session struct {
		paramsID,
		algorithm,
		protocol int
		party tss.Party
	}
)

var (
	// Params builders
	params []*tss.Parameters
	// LocalParty sessions
	sessions         []*session
	sessionOutChs    []<-chan tss.Message
	sessionKeyEndChs []<-chan keygen.LocalPartySaveData
	sessionSigEndChs []<-chan signing.LocalSignData
)

func init() {
	params = make([]*tss.Parameters, 0, 5)
	sessions = make([]*session, 0, 5)
	sessionOutChs = make([]<-chan tss.Message, 0, 5)
	sessionKeyEndChs = make([]<-chan keygen.LocalPartySaveData, 0, 5)
	sessionSigEndChs = make([]<-chan signing.LocalSignData, 0, 5)
}

// ----- //

func GeneratePreParams() (jsonPreParams []byte, err error) {
	preParams, err := keygen.GeneratePreParams()
	if err != nil {
		return nil, err
	}
	return json.Marshal(&preParams)
}

func GenerateLocalSaveData() (jsonSaveData []byte, err error) {
	preParams, err := keygen.GeneratePreParams()
	if err != nil {
		return nil, err
	}
	saveData := keygen.LocalPartySaveData{
		LocalPreParams: *preParams,
	}
	return json.Marshal(&saveData)
}

// ----- //

func InitParamsBuilder(ourID, ourMoniker string, ourKey int64, partyCount, threshold int) (paramsID int) {
	partyID := tss.NewPartyID(ourID, ourMoniker, new(big.Int).SetInt64(ourKey))
	peerCtx := tss.NewPeerContext(tss.SortedPartyIDs{partyID})
	params = append(params, tss.NewParameters(peerCtx, partyID, partyCount, threshold))
	return len(params) - 1
}

func AddPartyToParams(paramsID int, pID, pMoniker string, pKey int64) (partyCount int, err error) {
	params, err := getParams(paramsID)
	if err != nil {
		return -1, err
	}
	partyIDs := params.Parties().IDs().ToUnSorted()
	partyID := tss.NewPartyID(pID, pMoniker, new(big.Int).SetInt64(pKey))
	partyIDs = append(partyIDs, partyID)
	params.Parties().SetIDs(tss.SortPartyIDs(partyIDs))
	return len(partyIDs), nil
}

// ----- //

func InitKeygenSession(paramsID, algorithm int, jsonPreParams []byte) (sessionID int, err error) {
	params, err := getParams(paramsID)
	if err != nil {
		return -1, err
	}
	sessionOutCh := make(chan tss.Message, len(params.Parties().IDs()))
	sessionOutChs = append(sessionOutChs, sessionOutCh)
	sessionKeyEndCh := make(chan keygen.LocalPartySaveData, 1)
	sessionKeyEndChs = append(sessionKeyEndChs, sessionKeyEndCh)
	sessionSigEndChs = append(sessionSigEndChs, nil)
	var preParams keygen.LocalPreParams
	if err := json.Unmarshal(jsonPreParams, &preParams); err != nil {
		return -1, err
	}
	party := keygen.NewLocalParty(params, sessionOutCh, sessionKeyEndCh, preParams)
	sessionID = len(sessions)
	sessions = append(sessions, &session{
		paramsID:  paramsID,
		algorithm: algorithm,
		protocol:  ProtocolKeygen,
		party:     party,
	})
	if err := party.Start(); err != nil {
		return sessionID, err
	}
	return sessionID, nil
}

func InitSigningSession(paramsID, algorithm int, msg, jsonKeyData []byte) (sessionID int, err error) {
	params, err := getParams(paramsID)
	if err != nil {
		return -1, err
	}
	sessionOutCh := make(chan tss.Message, len(params.Parties().IDs()))
	sessionOutChs = append(sessionOutChs, sessionOutCh)
	sessionKeyEndChs = append(sessionKeyEndChs, nil)
	sessionSigEndCh := make(chan signing.LocalSignData, 1)
	sessionSigEndChs = append(sessionSigEndChs, sessionSigEndCh)
	msgInt := new(big.Int).SetBytes(msg)
	var keyData keygen.LocalPartySaveData
	if err := json.Unmarshal(jsonKeyData, &keyData); err != nil {
		return -1, err
	}
	party := signing.NewLocalParty(msgInt, params, keyData, sessionOutCh, sessionSigEndCh)
	sessionID = len(sessions)
	sessions = append(sessions, &session{
		paramsID:  paramsID,
		algorithm: algorithm,
		protocol:  ProtocolKeygen,
		party:     party,
	})
	if err := party.Start(); err != nil {
		return sessionID, err
	}
	return sessionID, nil
}

// ----- //

func PollKeygenSession(sessionID int) (data []byte, err error) {
	if _, err := getSession(sessionID); err != nil {
		return nil, err
	}
	outCh, endCh := sessionOutChs[sessionID], sessionKeyEndChs[sessionID]
	select {
	case msg := <-outCh:
		return msg.WireBytes()
	case save := <-endCh:
		return json.Marshal(&save)
	}
}

func PollSigningSession(sessionID int) (data []byte, err error) {
	if _, err := getSession(sessionID); err != nil {
		return nil, err
	}
	outCh, endCh := sessionOutChs[sessionID], sessionSigEndChs[sessionID]
	select {
	case msg := <-outCh:
		return msg.WireBytes()
	case sigData := <-endCh:
		return json.Marshal(&sigData)
	}
}

// ----- //

func UpdateSession(sessionID, fromPartyIdx int, wireMsg []byte) (ok bool, err error) {
	session, err := getSession(sessionID)
	if err != nil {
		return false, err
	}
	params, err := getParams(session.paramsID)
	if err != nil {
		return false, err
	}
	parties := params.Parties().IDs()
	var from *tss.PartyID
	if fromPartyIdx > 0 {
		from = parties[fromPartyIdx]
	}
	return session.party.UpdateFromBytes(wireMsg, from)
}

// ----- //

func GetSessionAlgorithm(sessionID int) (string, error) {
	session, err := getSession(sessionID)
	if err != nil {
		return "", err
	}
	switch session.algorithm {
	case AlgorithmECDSA:
		return "ECDSA", nil
	}
	return "", errors.New("session uses an unknown algorithm")
}

func GetSessionProtocol(sessionID int) (string, error) {
	session, err := getSession(sessionID)
	if err != nil {
		return "", err
	}
	switch session.protocol {
	case ProtocolKeygen:
		return "keygen", nil
	case ProtocolSigning:
		return "signing", nil
	case ProtocolReSharing:
		return "resharing", nil
	}
	return "", errors.New("session uses an unknown algorithm")
}

func DestroySession(sessionID int) error {
	if _, err := getSession(sessionID); err != nil {
		return err
	}
	sessions[sessionID] = nil
	if sessionOutChs[sessionID] != nil {
		sessionOutChs[sessionID] = nil
	}
	if sessionKeyEndChs[sessionID] != nil {
		sessionKeyEndChs[sessionID] = nil
	}
	if sessionSigEndChs[sessionID] != nil {
		sessionSigEndChs[sessionID] = nil
	}
	return nil
}

// ----- //

func getParams(paramsID int) (*tss.Parameters, error) {
	if paramsID < len(params) {
		if params[paramsID] == nil {
			return nil, errors.New("that session has been ended")
		}
		return params[paramsID], nil
	}
	return nil, errors.New("that session does not exist")
}

func getSession(sessionID int) (*session, error) {
	if sessionID < len(sessions) {
		if sessions[sessionID] == nil {
			return nil, errors.New("that session has been ended")
		}
		return sessions[sessionID], nil
	}
	return nil, errors.New("that session does not exist")
}
