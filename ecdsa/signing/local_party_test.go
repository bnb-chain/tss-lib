package signing

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

	threshold := testThreshold
	pIDs := tss.GenerateTestPartyIDs(testParticipants)
	keys := make([]keygen.LocalPartySaveData, len(pIDs), len(pIDs))

	// PHASE: load keygen fixtures
	for j := 0; j < len(pIDs); j++ {
		fixtureFilePath := keygen.MakeTestFixtureFilePath(j)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if assert.NoErrorf(t, err,
			"could not find a test fixture for party %d in the expected location: %s. run keygen tests first.",
			j, fixtureFilePath) {
			var key keygen.LocalPartySaveData
			err = json.Unmarshal(bz, &key)
			if assert.NoErrorf(t, err, "should unmarshal fixture data for party %d", j) {
				keys[j] = key
				common.Logger.Infof("Loaded test key fixture for party %d: %s", j, fixtureFilePath)
				continue
			}
		}
		t.FailNow()
	}

	// PHASE: signing
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
signing:
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
				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
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

				break signing
			}
		}
	}
}
