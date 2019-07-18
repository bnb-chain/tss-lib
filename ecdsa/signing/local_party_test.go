package signing

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
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
	setUp("info")

	// tss.SetCurve(elliptic.P256())

	pIDs := tss.GenerateTestPartyIDs(testParticipants)
	for _, pid := range pIDs {
		fmt.Println(pid.Key.String())
	}
	threshold := testThreshold

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	out := make(chan tss.Message, len(pIDs))
	end := make(chan keygen.LocalPartySaveData, len(pIDs))

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
							if _, err := P.Update(msg, "keygen"); err != nil {
								common.Logger.Errorf("Error: %s", err)
								assert.FailNow(t, err.Error()) // TODO fail outside goroutine
							}
						}(P, msg)
					}
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go func(P *keygen.LocalParty) {
					if _, err := P.Update(msg, "keygen"); err != nil {
						common.Logger.Errorf("Error: %s", err)
						assert.FailNow(t, err.Error()) // TODO fail outside goroutine
					}
				}(parties[dest[0].Index])
			}
		case save := <-end:
			atomic.AddInt32(&ended, 1)
			keys[save.Index] = save
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// more verification of signing is implemented within local_party_test.go of keygen package
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
		P := NewLocalParty(big.NewInt(42), params, keys[i], signOut, signEnd)
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
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go func(P *LocalParty, msg tss.Message) {
						if _, err := P.Update(msg, "sign"); err != nil {
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
					if _, err := P.Update(msg, "sign"); err != nil {
						common.Logger.Errorf("Error: %s", err)
						assert.FailNow(t, err.Error()) // TODO fail outside goroutine
					}
				}(signParties[dest[0].Index])
			}
		case <-signEnd:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				t.Logf("Done. Received save data from %d participants", signEnded)
				R := signParties[0].temp.bigR
				r := signParties[0].temp.r
				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.EC().Params().N)

				// BEGIN check R correctness
				sumK := big.NewInt(0)
				for _, p := range signParties {
					sumK = modN.Add(sumK, p.temp.k)
				}
				sumGamma := big.NewInt(0)
				for _, p := range signParties {
					sumGamma = modN.Add(sumGamma, p.temp.gamma)
				}
				sumTheta := big.NewInt(0)
				for _, p := range signParties {
					sumTheta = modN.Add(sumTheta, p.temp.thelta)
				}
				assert.Equal(t, sumTheta, modN.Mul(sumGamma, sumK))
				sumKInverse := modN.ModInverse(sumK)
				rx, ry := tss.EC().ScalarBaseMult(sumKInverse.Bytes())
				assert.Equal(t, rx, R.X())
				assert.Equal(t, ry, R.Y())
				//END check R correctness

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range signParties {
					sumS = modN.Add(sumS, p.temp.si)
				}
				fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(), R.X(), sumS)
				assert.True(t, ok)
				// END ECDSA verify

				// BEGIN VVV verify
				sumL := big.NewInt(0)
				for _, p := range signParties {
					sumL = modN.Add(sumL, p.temp.li)
				}
				VVVX, VVVY := tss.EC().ScalarBaseMult(sumL.Bytes())
				assert.Equal(t, VVVX, signParties[0].temp.VVV.X())
				assert.Equal(t, VVVY, signParties[0].temp.VVV.Y())
				// END VVV verify
				return
			}
		}
	}
}
