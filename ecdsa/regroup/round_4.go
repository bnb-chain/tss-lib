package regroup

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.receiving = false
	round.resetOK() // resets both round.oldOK and round.newOK

	if round.ReGroupParams().IsOldCommittee() {
		return nil // old committee finished!
	}

	// 1.
	newXi := big.NewInt(0)

	// 2-11.
	modQ := common.ModInt(tss.EC().Params().N)
	vjc := make([][]*crypto.ECPoint, round.Threshold() + 1)
	for j := 0; j <= round.Threshold(); j++ { // P1..P_t+1. Ps are indexed from 0 here
		// 3-4.
		cj := round.temp.dgRound1OldCommitteeCommitMessages[j].Commitment
		dj := round.temp.dgRound3DeCommitMessage[j].DeCommitment
		cmtDeCmt := commitments.HashCommitDecommit{C: cj, D: dj}
		ok, flat := cmtDeCmt.DeCommit()
		if !ok || len(flat) != (round.NewThreshold() + 1) * 2 { // they're points so * 2
			return round.WrapError(errors.New("decommitment of v_j0..v_jt failed"), round.Parties().IDs()[j])
		}
		vj, err := crypto.UnFlattenECPoints(nil, flat)
		if err != nil {
			return round.WrapError(err, round.Parties().IDs()[j])
		}
		vjc[j] = vj

		// 5.
		Xj := round.temp.BigXs[j]
		if !vj[0].Equals(Xj) {
			return round.WrapError(errors.New("v_j0 did not equal X_j"), round.Parties().IDs()[j])
		}

		// 6.
		sharej := round.temp.dgRound3ShareMessage[j]
		if ok := sharej.Share.Verify(round.NewThreshold(), vj); !ok {
			return round.WrapError(errors.New("share from old committee did not pass Verify()"), round.Parties().IDs()[j])
		}

		// 7-10.
		iota := sharej.Share.Share
		for c := 0; c <= round.Threshold(); c++ { // P1..P_t+1. Ps are indexed from 0 here
			if j == c {
				continue
			}
			kc, kj := round.key.Ks[c], round.key.Ks[j]
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			coef := modQ.Mul(kc, modQ.ModInverse(new(big.Int).Sub(kc, kj)))
			iota = modQ.Mul(iota, coef)
		}

		// 11.
		newXi = new(big.Int).Add(newXi, iota)
	}

	// 12-15.
	Vc := make([]*crypto.ECPoint, round.NewThreshold() + 1)
	for c := 0; c <= round.NewThreshold(); c++ {
		Vc[c] = crypto.NewECPoint(tss.EC(), big.NewInt(1), big.NewInt(1))
		for j := 0; j <= round.Threshold(); j++ {
			Vc[c] = Vc[c].Add(vjc[j][c])
		}
	}

	// 16-20.
	NewBigXj := make([]*crypto.ECPoint, round.NewPartyCount())
	for j := 0; j < round.NewPartyCount(); j++ {
		NewBigXj[j] = Vc[0]
		for c := 0; c < round.NewThreshold(); c++ {
			newKj := round.NewParties().IDs()[j].Key
			z := modQ.Exp(newKj, big.NewInt(int64(c)))
			NewBigXj[j] = NewBigXj[j].Add(Vc[c].ScalarMult(z))
		}
	}

	// 21.
	round.save.Xi = newXi
	round.save.BigXj = NewBigXj

	return nil
}

func (round *round4) CanAccept(msg tss.Message) bool {
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
