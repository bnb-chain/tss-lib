package signing

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 10
	round.started = true
	round.resetOk()

	sumS := round.temp.si
	for j := range round.Parties().Parties() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		sumS = new(big.Int).Add(sumS, round.temp.signRound9SignatureMessage[j].Si)
	}

	// TODO: confirm with steven this is safe!!!
	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(tss.EC().Params().N, 1)
	if sumS.Cmp(secp256k1halfN) > 0 {
		sumS.Sub(tss.EC().Params().N, sumS)
	}

	round.data.Signature = append(round.temp.r.Bytes(), sumS.Bytes()...)

	return nil
}

func (round *finalization) CanAccept(msg tss.Message) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
