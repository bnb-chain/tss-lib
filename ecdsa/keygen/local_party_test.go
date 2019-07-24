package keygen

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = 20
	testThreshold    = testParticipants / 2
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestStartKeygenRound1Paillier(t *testing.T) {
	setUp("debug")

	pIDs := tss.GenerateTestPartyIDs(1)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(p2pCtx, pIDs[0], len(pIDs), threshold)

	out := make(chan tss.Message, len(pIDs))
	lp := NewLocalParty(params, out, nil)
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}
	_ = <-out

	// Paillier modulus 2048 (two 1024-bit primes)
	assert.Equal(t, 2048/8, len(lp.data.PaillierSk.LambdaN.Bytes()))
	assert.Equal(t, 2048/8, len(lp.data.PaillierSk.PublicKey.N.Bytes()))
}

func TestStartKeygenRound1RSA(t *testing.T) {
	setUp("debug")

	pIDs := tss.GenerateTestPartyIDs(1)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(p2pCtx, pIDs[0], len(pIDs), threshold)

	out := make(chan tss.Message, len(pIDs))
	lp := NewLocalParty(params, out, nil)
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}

	// RSA modulus 2048 (two 1024-bit primes)
	assert.Equal(t, 2048/8, len(lp.data.NTildej[pIDs[0].Index].Bytes()))
	assert.Equal(t, 2048/8, len(lp.data.H1j[pIDs[0].Index].Bytes()))
	assert.Equal(t, 2048/8, len(lp.data.H2j[pIDs[0].Index].Bytes()))
}

func TestFinishAndSaveKeygenH1H2(t *testing.T) {
	setUp("debug")

	pIDs := tss.GenerateTestPartyIDs(1)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(p2pCtx, pIDs[0], len(pIDs), threshold)

	out := make(chan tss.Message, len(pIDs))
	lp := NewLocalParty(params, out, nil)
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}

	// RSA modulus 2048 (two 1024-bit primes)
	// round up to 256
	len1 := len(lp.data.H1j[0].Bytes())
	len2 := len(lp.data.H2j[0].Bytes())
	if len1 % 2 != 0 {
		len1 = len1 + (256 - (len1 % 256))
	}
	if len2 % 2 != 0 {
		len2 = len2 + (256 - (len2 % 256))
	}
	assert.Equal(t, 256, len1, "h1 should be correct len")
	assert.Equal(t, 256, len2, "h2 should be correct len")
	assert.NotZero(t, lp.data.H1j, "h1 should be non-zero")
	assert.NotZero(t, lp.data.H2j, "h2 should be non-zero")
}

func TestUpdateBadMessageCulprits(t *testing.T) {
	setUp("debug")

	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(p2pCtx, pIDs[0], len(pIDs), threshold)

	out := make(chan tss.Message, len(pIDs))
	lp := NewLocalParty(params, out, nil)
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}

	badMsg := NewKGRound1CommitMessage(pIDs[1], nil, nil, nil, nil, nil)
	ok, err := lp.Update(badMsg, "keygen")
	t.Log(err)
	assert.False(t, ok)
	assert.Error(t, err)
	assert.Equal(t, 1, len(err.Culprits()))
	assert.Equal(t, pIDs[1], err.Culprits()[0])
	assert.Equal(t,
		"task keygen, party {0,P[1]}, round 1, culprits [{1,P[2]}]: message failed ValidateBasic: Type: KGRound1CommitMessage, From: {1,P[2]}, To: all",
		err.Error())
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")

	// tss.SetCurve(elliptic.P256())

	pIDs := tss.GenerateTestPartyIDs(testParticipants)
	threshold := testThreshold

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	out := make(chan tss.Message, len(pIDs))
	end := make(chan LocalPartySaveData, len(pIDs))

	startGR := runtime.NumGoroutine()

	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(p2pCtx, pIDs[i], len(pIDs), threshold)
		P := NewLocalParty(params, out, end)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
	datas := make([]LocalPartyTempData, 0, len(pIDs))
	dmtx := sync.Mutex{}
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-out:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go func(P *LocalParty, msg tss.Message) {
						if _, err := P.Update(msg, "keygen"); err != nil {
							common.Logger.Errorf("Error: %s", err)
							assert.FailNow(t, err.Error()) // TODO fail outside goroutine
						}
					}(P, msg)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go func(P *LocalParty) {
					if _, err := P.Update(msg, "keygen"); err != nil {
						common.Logger.Errorf("Error: %s", err)
						assert.FailNow(t, err.Error()) // TODO fail outside goroutine
					}
				}(parties[dest[0].Index])
			}
		case save := <-end:
			dmtx.Lock()
			for _, P := range parties {
				datas = append(datas, P.temp)
			}
			dmtx.Unlock()
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for j2, P := range parties {
						if j2 == j {
							continue
						}
						vssMsgs := P.temp.kgRound2VssMessages
						pShares = append(pShares, vssMsgs[j].PiShare)
					}
					uj, err := pShares[:threshold+1].ReConstruct()
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.temp.ui)
					uGX, uGY := tss.EC().ScalarBaseMult(uj.Bytes())
					assert.Equal(t, uGX, Pj.temp.vs[0].X())
					assert.Equal(t, uGY, Pj.temp.vs[0].Y())

					// xj test: BigXj == xj*G
					xj := Pj.data.Xi
					gXjX, gXjY := tss.EC().ScalarBaseMult(xj.Bytes())
					BigXjX, BigXjY := Pj.data.BigXj[j].X(), Pj.data.BigXj[j].Y()
					assert.Equal(t, BigXjX, gXjX)
					assert.Equal(t, BigXjY, gXjY)

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, _ := pShares[:threshold].ReConstruct()
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.EC().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}

					u = new(big.Int).Add(u, uj)
				}

				// build ecdsa key pair
				pkX, pkY := save.ECDSAPub.X(), save.ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				sk := ecdsa.PrivateKey{
					PublicKey: pk,
					D:         u,
				}
				// test pub key, should be on curve and match pkX, pkY
				assert.True(t, sk.IsOnCurve(pkX, pkY), "public key must be on curve")

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := tss.EC().ScalarBaseMult(u.Bytes())
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same ECDSA public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.ECDSAPub.X())
					assert.Equal(t, pkY, Pj.data.ECDSAPub.Y())
				}
				t.Log("Public key distribution test done.")

				// test sign/verify
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
				assert.NoError(t, err, "sign should not throw an error")
				ok := ecdsa.Verify(&pk, data, r, s)
				assert.True(t, ok, "signature should be ok")
				t.Log("ECDSA signing test done.")

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				return
			}
		}
	}
}
