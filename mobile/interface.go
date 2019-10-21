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
	"time"

	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/resharing"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	AlgorithmECDSA = iota
)
const (
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
	// Params builders - we use ReSharingParams as it is a superset of Parameters
	params []*tss.ReSharingParameters
	// LocalParty sessions
	sessions         []*session
	sessionOutChs    []<-chan tss.Message
	sessionKeyEndChs []<-chan keygen.LocalPartySaveData
	sessionSigEndChs []<-chan signing.LocalSignData
)

func init() {
	params = make([]*tss.ReSharingParameters, 0, 5)
	sessions = make([]*session, 0, 5)
	sessionOutChs = make([]<-chan tss.Message, 0, 5)
	sessionKeyEndChs = make([]<-chan keygen.LocalPartySaveData, 0, 5)
	sessionSigEndChs = make([]<-chan signing.LocalSignData, 0, 5)
}

// ----- //

// GeneratePreParams generates pre-parameters like the Paillier keys and NTilde, H1, H2
func GeneratePreParams(timeoutDuration int64) (jsonPreParams []byte, err error) {
	preParams, err := keygen.GeneratePreParams(time.Duration(timeoutDuration))
	if err != nil {
		return nil, err
	}
	return json.Marshal(&preParams)
}

// GenerateLocalSaveData generates pre-parameters like the Paillier keys and NTilde, H1, H2 in a full local save data object
func GenerateLocalSaveData(timeoutDuration int64) (jsonSaveData []byte, err error) {
	preParams, err := keygen.GeneratePreParams(time.Duration(timeoutDuration))
	if err != nil {
		return nil, err
	}
	saveData := keygen.LocalPartySaveData{
		LocalPreParams: *preParams,
	}
	return json.Marshal(&saveData)
}

// ----- //

// InitParamsBuilder initialises a *tss.Parameters builder that works in a gomobile binding
func InitParamsBuilder(ourID, ourMoniker string, ourKey int64, partyCount, threshold int) (paramsID int) {
	partyID := tss.NewPartyID(ourID, ourMoniker, new(big.Int).SetInt64(ourKey))
	peerCtx := tss.NewPeerContext(tss.SortedPartyIDs{partyID})
	params = append(params, &tss.ReSharingParameters{
		Parameters: tss.NewParameters(peerCtx, partyID, partyCount, threshold),
	})
	return len(params) - 1
}

// InitReSharingParamsBuilder initialises a *tss.ReSharingParameters builder that works in a gomobile binding
func InitReSharingParamsBuilder(ourID, ourMoniker string, ourKey int64, partyCount, threshold, newPartyCount, newThreshold int, usNewCommittee bool) (paramsID int) {
	partyID := tss.NewPartyID(ourID, ourMoniker, new(big.Int).SetInt64(ourKey))
	usPeerCtx := tss.NewPeerContext(tss.SortedPartyIDs{partyID})
	emptyPeerCtx := tss.NewPeerContext(tss.SortedPartyIDs{})
	var reSharingParams *tss.ReSharingParameters
	if usNewCommittee {
		reSharingParams = tss.NewReSharingParameters(emptyPeerCtx, usPeerCtx, partyID, partyCount, threshold, newPartyCount, newThreshold)
	} else {
		reSharingParams = tss.NewReSharingParameters(usPeerCtx, emptyPeerCtx, partyID, partyCount, threshold, newPartyCount, newThreshold)
	}
	params = append(params, reSharingParams)
	return len(params) - 1
}

// AddPartyToParams adds a PartyID to a local *tss.Parameters (in the case of the ReSharing protocol, this refers to the old committee)
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

// AddPartyToReSharingParams adds a PartyID to a local *tss.ReSharingParameters (the new committee in ReSharing)
func AddNewPartyToReSharingParams(paramsID int, pID, pMoniker string, pKey int64) (newPartyCount int, err error) {
	params, err := getReSharingParams(paramsID)
	if err != nil {
		return -1, err
	}
	partyIDs := params.Parties().IDs().ToUnSorted()
	partyID := tss.NewPartyID(pID, pMoniker, new(big.Int).SetInt64(pKey))
	partyIDs = append(partyIDs, partyID)
	params.NewParties().SetIDs(tss.SortPartyIDs(partyIDs))
	return len(partyIDs), nil
}

// ----- //

// InitKeygenSession starts a new keygen session
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
		protocol:  ProtocolKeygen,
		paramsID:  paramsID,
		algorithm: algorithm,
		party:     party,
	})
	if err := party.Start(); err != nil {
		return sessionID, err
	}
	return sessionID, nil
}

// InitSigningSession starts a new signing session
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
		protocol:  ProtocolSigning,
		paramsID:  paramsID,
		algorithm: algorithm,
		party:     party,
	})
	if err := party.Start(); err != nil {
		return sessionID, err
	}
	return sessionID, nil
}

// InitReSharingSession starts a new re-sharing session
func InitReSharingSession(paramsID, algorithm int, jsonKeyData []byte) (sessionID int, err error) {
	params, err := getReSharingParams(paramsID)
	if err != nil {
		return -1, err
	}
	sessionOutCh := make(chan tss.Message, len(params.Parties().IDs()))
	sessionOutChs = append(sessionOutChs, sessionOutCh)
	sessionKeyEndCh := make(chan keygen.LocalPartySaveData, 1)
	sessionKeyEndChs = append(sessionKeyEndChs, sessionKeyEndCh)
	sessionSigEndChs = append(sessionSigEndChs, nil)
	var keyData keygen.LocalPartySaveData
	if err := json.Unmarshal(jsonKeyData, &keyData); err != nil {
		return -1, err
	}
	party := resharing.NewLocalParty(params, keyData, sessionOutCh, sessionKeyEndCh)
	sessionID = len(sessions)
	sessions = append(sessions, &session{
		protocol:  ProtocolReSharing,
		paramsID:  paramsID,
		algorithm: algorithm,
		party:     party,
	})
	if err := party.Start(); err != nil {
		return sessionID, err
	}
	return sessionID, nil
}

// ----- //

// PollKeygenOrReSharingSession waits for a message to come from an active keygen or re-sharing session through its LocalParty's out or end channels
func PollKeygenOrReSharingSession(sessionID int) (data []byte, err error) {
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

// PollSigningSession waits for a message to come from an active signing session through its LocalParty's out or end channels
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

// UpdateSession updates an active session's LocalParty with an incoming message from the wire
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

// GetSessionAlgorithm returns an active session's algorithm (ECDSA, ...)
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

// GetSessionProtocol returns an active session's protocol (keygen, signing, resharing, ...)
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

// DestroySession destroys an active session (sets the LocalParty reference and its out and end channels to nil)
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
			return nil, errors.New("params with that ID does not exist")
		}
		return params[paramsID].Parameters, nil
	}
	return nil, errors.New("that session does not exist")
}

func getReSharingParams(paramsID int) (*tss.ReSharingParameters, error) {
	if paramsID < len(params) {
		if params[paramsID] == nil {
			return nil, errors.New("params with that ID does not exist")
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
