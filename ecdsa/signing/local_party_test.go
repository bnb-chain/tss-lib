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

	threshold := testThreshold
	pIDs := tss.GenerateTestPartyIDs(testParticipants)

	// PHASE: load keygen fixtures
	keys, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: signing
	signPIDs := pIDs[:threshold+1]

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan LocalPartySignData, len(signPIDs))

	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(p2pCtx, signPIDs[i], len(signPIDs), threshold)
		P := NewLocalParty(big.NewInt(42), params, keys[i], outCh, endCh)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go func(P *LocalParty, msg tss.Message) {
						if _, err := P.Update(msg, "sign"); err != nil {
							errCh <- err
						}
					}(P, msg)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go func(P *LocalParty) {
					if _, err := P.Update(msg, "sign"); err != nil {
						errCh <- err
					}
				}(parties[dest[0].Index])
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)
				R := parties[0].temp.bigR
				r := parties[0].temp.rx
				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.EC().Params().N)

				// BEGIN check R correctness
				sumK := big.NewInt(0)
				for _, p := range parties {
					sumK = modN.Add(sumK, p.temp.k)
				}
				sumGamma := big.NewInt(0)
				for _, p := range parties {
					sumGamma = modN.Add(sumGamma, p.temp.gamma)
				}
				sumTheta := big.NewInt(0)
				for _, p := range parties {
					sumTheta = modN.Add(sumTheta, p.temp.theta)
				}
				assert.Equal(t, sumTheta, modN.Mul(sumGamma, sumK))
				sumKInverse := modN.ModInverse(sumK)
				rx, ry := tss.EC().ScalarBaseMult(sumKInverse.Bytes())
				assert.Equal(t, rx, R.X())
				assert.Equal(t, ry, R.Y())
				// END check R correctness

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
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
				for _, p := range parties {
					sumL = modN.Add(sumL, p.temp.li)
				}
				VVVX, VVVY := tss.EC().ScalarBaseMult(sumL.Bytes())
				assert.Equal(t, VVVX, parties[0].temp.VVV.X())
				assert.Equal(t, VVVY, parties[0].temp.VVV.Y())
				// END VVV verify

				break signing
			}
		}
	}
}
