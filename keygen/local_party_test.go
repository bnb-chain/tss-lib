package keygen_test

import (
	"sync"
	"testing"
	"time"

	"github.com/ipfs/go-log"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/keygen"
	"github.com/binance-chain/tss-lib/types"
)

const (
	TestParticipants = 20
)

func setUp() {
	if err := log.SetLogLevel("tss-lib", "info"); err != nil {
		panic(err)
	}
}

func TestLocalPartyE2EConcurrent(t *testing.T) {
	setUp()

	pIDs := types.GeneratePartyIDs(TestParticipants)
	p2pCtx := types.NewPeerContext(pIDs)
	players := make([]*keygen.LocalParty, 0, len(pIDs))
	pmtxs := make([]sync.Mutex, len(pIDs))
	params := keygen.NewKGParameters(len(pIDs), len(pIDs) / 2)

	out := make(chan types.Message, len(pIDs))
	end := make(chan keygen.LocalPartySaveData, len(pIDs))

	for i := 0; i < len(pIDs); i++ {
		P := keygen.NewLocalParty(p2pCtx, *params, pIDs[i], out, end)
		players = append(players, P)
		go func(P *keygen.LocalParty) {
			pmtxs[P.ID().Index].Lock()
			if err := P.StartKeygenRound1(); err != nil {
				common.Logger.Errorf("Error: %s", err)
				panic(err)
			}
			pmtxs[P.ID().Index].Unlock()
		}(P)
	}

	ended := 0
	for {
		select {
		case msg := <-out:
			dest := msg.GetTo()
			if dest == nil {
				// broadcast
				for _, P := range players {
					go func(P *keygen.LocalParty, msg types.Message) {
						pmtxs[P.ID().Index].Lock()
						if _, err := P.Update(msg); err != nil {
							common.Logger.Errorf("Error: %s", err)
							panic(err)
						}
						pmtxs[P.ID().Index].Unlock()
					}(P, msg)
				}
			} else {
				go func(P *keygen.LocalParty) {
					pmtxs[P.ID().Index].Lock()
					if _, err := P.Update(msg); err != nil {
						common.Logger.Errorf("Error: %s", err)
						panic(err)
					}
					pmtxs[P.ID().Index].Unlock()
				}(players[dest.Index])
			}
		case <-end:
			ended++
			if ended >= len(pIDs) {
				time.Sleep(100 * time.Millisecond)
				t.Logf("Done. Received save data from %d participants", ended)
				return
			}
		}
	}
}
