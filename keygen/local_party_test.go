package keygen

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/types"
)

const (
	TestParticipants = 20
	TestThreshold = TestParticipants / 2
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestStartKeygenRound1Paillier(t *testing.T) {
	setUp("debug")

	pIDs := types.GeneratePartyIDs(1)
	p2pCtx := types.NewPeerContext(pIDs)
	threshold := 1
	params := NewKGParameters(len(pIDs), threshold)

	out := make(chan types.Message, len(pIDs))
	lp := NewLocalParty(p2pCtx, *params, pIDs[0], out, nil)
	if err := lp.StartKeygenRound1(); err != nil {
		assert.FailNow(t, err.Error())
	}
	_ = <-out

	// Paillier modulus 2048 (two 1024-bit primes)
	assert.Equal(t, 2048 / 8, len(lp.data.PaillierSk.L.Bytes()))
	assert.Equal(t, 2048 / 8, len(lp.data.PaillierSk.PublicKey.N.Bytes()))
}
func TestStartKeygenRound1RSA(t *testing.T) {
	setUp("debug")

	pIDs := types.GeneratePartyIDs(1)
	p2pCtx := types.NewPeerContext(pIDs)
	threshold := 1
	params := NewKGParameters(len(pIDs), threshold)

	out := make(chan types.Message, len(pIDs))
	lp := NewLocalParty(p2pCtx, *params, pIDs[0], out, nil)
	if err := lp.StartKeygenRound1(); err != nil {
		assert.FailNow(t, err.Error())
	}
	_ = <-out

	// RSA modulus 2048 (two 1024-bit primes)
	assert.Equal(t, 2, len(lp.data.RSAKey.Primes))
	assert.Equal(t, 1024 / 8, len(lp.data.RSAKey.Primes[0].Bytes()))
	assert.Equal(t, 1024 / 8, len(lp.data.RSAKey.Primes[1].Bytes()))
	assert.Equal(t, 2048 / 8, len(lp.data.RSAKey.PublicKey.N.Bytes()))
}

func TestLocalPartyE2EConcurrent(t *testing.T) {
	setUp("info")

	pIDs := types.GeneratePartyIDs(TestParticipants)
	threshold := TestThreshold

	p2pCtx := types.NewPeerContext(pIDs)
	players := make([]*LocalParty, 0, len(pIDs))
	pmtxs := make([]sync.Mutex, len(pIDs))
	params := NewKGParameters(len(pIDs), threshold)

	out := make(chan types.Message, len(pIDs))
	end := make(chan LocalPartySaveData, len(pIDs))

	for i := 0; i < len(pIDs); i++ {
		P := NewLocalParty(p2pCtx, *params, pIDs[i], out, end)
		players = append(players, P)
		go func(P *LocalParty) {
			pmtxs[P.ID().Index].Lock()
			if err := P.StartKeygenRound1(); err != nil {
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
			}
			pmtxs[P.ID().Index].Unlock()
		}(P)
	}

	var ended int32
	datas := make([]LocalPartySaveData, 0, len(pIDs))
	dmtx := sync.Mutex{}
	for {
		select {
		case msg := <-out:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range players {
					go func(P *LocalParty, msg types.Message) {
						pmtxs[P.ID().Index].Lock()
						if _, err := P.Update(msg); err != nil {
							common.Logger.Errorf("Error: %s", err)
							assert.FailNow(t, err.Error())
						}
						pmtxs[P.ID().Index].Unlock()
					}(P, msg)
				}
			} else {
				go func(P *LocalParty) {
					pmtxs[P.ID().Index].Lock()
					if _, err := P.Update(msg); err != nil {
						common.Logger.Errorf("Error: %s", err)
						assert.FailNow(t, err.Error())
					}
					pmtxs[P.ID().Index].Unlock()
				}(players[dest.Index])
			}
		case data := <-end:
			dmtx.Lock()
			datas = append(datas, data)
			dmtx.Unlock()
			atomic.AddInt32(&ended, 1)
			ended++
			if atomic.LoadInt32(&ended) >= int32(len(pIDs)) {
				time.Sleep(100 * time.Millisecond)
				t.Logf("Done. Received save data from %d participants", ended)

				// calculate private key
				u := new(big.Int)
				for i, d := range datas {
					if i == 0 {
						continue
					}
					u = new(big.Int).Add(u, d.Ui)
				}

				// combine vss shares for each Pj to get x
				x := new(big.Int)
				for j := range players {
					pShares := make(vss.Shares, 0)
					for _, P := range players {
						vssMsgs := P.kgRound2VssMessages
						pShares = append(pShares, vssMsgs[j].PiShare)
					}
					xi, err := pShares[:threshold].Combine()  // fail if threshold-1
					assert.NoError(t, err, "vss.Combine should not throw error")
					x = new(big.Int).Add(x, xi)
				}

				// build ecdsa key pair
				pkX, pkY := data.PkX, data.PkY
				pk := ecdsa.PublicKey{
					Curve: EC(),
					X:     pkX,
					Y:     pkY,
				}
				sk := ecdsa.PrivateKey{
					PublicKey: pk,
					D:         x,
				}

				// test pub key, should be on curve and match pkX, pkY
				assert.True(t, sk.IsOnCurve(pkX, pkY), "public key must be on curve")

				ourPkX, ourPkY := EC().ScalarBaseMult(x.Bytes())
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from x")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from x")
				t.Log("Public key tests passed.")

				// test sign/verify
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
				assert.NoError(t, err, "sign should not throw an error")
				ok := ecdsa.Verify(&pk, data, r, s)
				assert.True(t, ok, "signature should be ok")
				t.Log("ECDSA signing test passed.")

				return
			}
		}
	}
}
