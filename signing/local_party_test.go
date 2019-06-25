package signing

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/keygen"
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

func TestE2EConcurrent(t *testing.T) {
	setUp("debug")

	// tss.SetCurve(elliptic.P256())

	pIDs := tss.GenerateTestPartyIDs(testParticipants)
	threshold := testThreshold

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	out := make(chan tss.Message, len(pIDs))
	end := make(chan keygen.LocalPartySaveData, len(pIDs))

	startGR := runtime.NumGoroutine()

	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(p2pCtx, pIDs[i], len(pIDs), threshold)
		P := keygen.NewLocalParty(params, out, end)
		parties = append(parties, P)
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
			}
		}(P)
	}

	var ended int32
	datas := make([]keygen.LocalPartyTempData, 0, len(pIDs))
	keys := make([]keygen.LocalPartySaveData, len(pIDs), len(pIDs))
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-out:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index != msg.GetFrom().Index {
						go func(P *keygen.LocalParty, msg tss.Message) {
							if _, err := P.Update(msg); err != nil {
								common.Logger.Errorf("Error: %s", err)
								assert.FailNow(t, err.Error()) // TODO fail outside goroutine
							}
						}(P, msg)
					}
				}
			} else {
				if dest.Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest.Index, msg.GetFrom().Index)
				}
				go func(P *keygen.LocalParty) {
					if _, err := P.Update(msg); err != nil {
						common.Logger.Errorf("Error: %s", err)
						assert.FailNow(t, err.Error()) // TODO fail outside goroutine
					}
				}(parties[dest.Index])
			}
		case save := <-end:
			atomic.AddInt32(&ended, 1)
			keys[save.Index] = save
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				for _, P := range parties {
					datas = append(datas, P.Temp)
				}

				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for j2, P := range parties {
						if j2 == j {
							continue
						}
						vssMsgs := P.Temp.KgRound2VssMessages
						pShares = append(pShares, vssMsgs[j].PiShare)
					}
					uj, err := pShares[:threshold].ReConstruct()
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.Temp.Ui)
					uGX, uGY := tss.EC().ScalarBaseMult(uj.Bytes())
					assert.Equal(t, uGX, Pj.Temp.PolyGs.PolyG[0].X())
					assert.Equal(t, uGY, Pj.Temp.PolyGs.PolyG[0].Y())

					// xj test: BigXj == xj*G
					xj := Pj.Data.Xi
					gXjX, gXjY := tss.EC().ScalarBaseMult(xj.Bytes())
					BigXjX, BigXjY := Pj.Data.BigXj[j].X(), Pj.Data.BigXj[j].Y()
					assert.Equal(t, BigXjX, gXjX)
					assert.Equal(t, BigXjY, gXjY)

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, _ := pShares[:threshold].ReConstruct()
						assert.NotEqual(t, parties[j].Temp.Ui, uj)
						BigXjX, BigXjY := tss.EC().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.Temp.PolyGs.PolyG[0].X())
						assert.NotEqual(t, BigXjY, Pj.Temp.PolyGs.PolyG[0].Y())
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
					assert.Equal(t, pkX, Pj.Data.ECDSAPub.X())
					assert.Equal(t, pkY, Pj.Data.ECDSAPub.Y())
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
				goto signing
			}
		}
	}

signing:
	signPIDs := pIDs[:testThreshold+1]

	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*LocalParty, 0, len(signPIDs))

	signOut := make(chan tss.Message, len(signPIDs))
	signEnd := make(chan LocalPartySignData, len(signPIDs))

	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(signP2pCtx, signPIDs[i], len(signPIDs), threshold)
		P := NewLocalParty(big.NewInt(0), params, keys[i], signOut, signEnd)
		signParties = append(signParties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
			}
		}(P)
	}

	var signEnded int32

	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-signOut:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index != msg.GetFrom().Index {
						go func(P *LocalParty, msg tss.Message) {
							if _, err := P.Update(msg); err != nil {
								common.Logger.Errorf("Error: %s", err)
								assert.FailNow(t, err.Error()) // TODO fail outside goroutine
							}
						}(P, msg)
					}
				}
			} else {
				if dest.Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest.Index, msg.GetFrom().Index)
				}
				go func(P *LocalParty) {
					if _, err := P.Update(msg); err != nil {
						common.Logger.Errorf("Error: %s", err)
						assert.FailNow(t, err.Error()) // TODO fail outside goroutine
					}
				}(signParties[dest.Index])
			}
		case save := <-signEnd:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				t.Logf("Done. Received save data from %d participants", signEnded)
				r := new(big.Int).Mod(save.R.X(), tss.EC().Params().N)
				fmt.Printf("sign result: R(%s, %s), r=%s\n", save.R.X().String(), save.R.Y().String(), r.String())

				// BEGIN check R correctness
				sumK := big.NewInt(0)
				for _, p := range signParties {
					sumK = new(big.Int).Mod(sumK.Add(sumK, p.temp.k), tss.EC().Params().N)
				}
				sumGamma := big.NewInt(0)
				for _, p := range signParties {
					sumGamma = new(big.Int).Mod(sumGamma.Add(sumGamma, p.temp.gamma), tss.EC().Params().N)
				}
				sumTheta := big.NewInt(0)
				for _, p := range signParties {
					sumTheta = new(big.Int).Mod(sumTheta.Add(sumTheta, p.temp.thelta), tss.EC().Params().N)
				}
				assert.Equal(t, sumTheta, new(big.Int).Mod(sumGamma.Mul(sumGamma, sumK), tss.EC().Params().N))
				sumKInverse := new(big.Int).ModInverse(sumK, tss.EC().Params().N)
				rx, ry := tss.EC().ScalarBaseMult(sumKInverse.Bytes())
				assert.Equal(t, rx, save.R.X())
				assert.Equal(t, ry, save.R.Y())
				//END check R correctness

				return
			}
		}
	}
}
