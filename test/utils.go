// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package test

import (
	"github.com/binance-chain/tss-lib/tss"
)

func SharedPartyUpdater(P tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- P.WrapError(err)
		return
	}
	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast(), msg.IsToOldCommittee())
	if err != nil {
		errCh <- P.WrapError(err)
		return
	}
	if _, err := P.Update(pMsg); err != nil {
		errCh <- err
	}
}
