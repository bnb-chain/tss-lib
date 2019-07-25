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
	round.resetOK() // resets both round.oldOK and round.newOK

	round.allOldOK()
	round.allNewOK()

	if !round.ReGroupParams().IsNewCommittee() {
		return nil // old committee finished!
	}

	Pi := round.PartyID()
	i := Pi.Index

	// save NTilde_j, h1_j, h2_j recieved in NewCommitteeStep1 here
	for j, msg := range round.temp.dgRound2PaillierPublicKeyMessage {
		if j == i {
			continue
		}
		round.save.NTildej[j] = msg.NTildei
		round.save.H1j[j] = msg.H1i
		round.save.H2j[j] = msg.H2i
	}

	// 1.
	newXi := big.NewInt(0)

	// 2-11.
	modQ := common.ModInt(tss.EC().Params().N)
	vjc := make([][]*crypto.ECPoint, round.Threshold() + 1)
	for j := 0; j <= round.Threshold(); j++ { // P1..P_t+1. Ps are indexed from 0 here
		// 3-4.
		vCj := round.temp.dgRound1OldCommitteeCommitMessages[j].VCommitment
		vDj := round.temp.dgRound3DeCommitMessage[j].VDeCommitment

		xAndKCj := round.temp.dgRound1OldCommitteeCommitMessages[j].XAndKCommitment
		xAndKDj := round.temp.dgRound3DeCommitMessage[j].XAndKDeCommitment

		// unpack compound commitment content (points are flattened and everything from round 1 was serialized together)
		xAndKCmtDeCmt := commitments.HashCommitDecommit{C: xAndKCj, D: xAndKDj}
		ok, serialized := xAndKCmtDeCmt.DeCommit()
		parsed, err := commitments.ParseSecrets(serialized)
		if err != nil {
			return round.WrapError(err, round.Parties().IDs()[j])
		}
		if len(parsed) < 2 {
			// TODO collect culprits and return a list of them as per convention
			return round.WrapError(errors.New("malformed second commitment; expected two parts"), round.Parties().IDs()[j])
		}
		round.temp.OldBigXj, err = crypto.UnFlattenECPoints(tss.EC(), parsed[0])
		if err != nil {
			return round.WrapError(err, round.Parties().IDs()[j])
		}
		round.temp.OldKs = parsed[1]

		// unpack flat "v" commitment content
		vCmtDeCmt := commitments.HashCommitDecommit{C: vCj, D: vDj}
	    ok, flatVs := vCmtDeCmt.DeCommit()
		if !ok || len(flatVs) != (round.NewThreshold() + 1) * 2 { // they're points so * 2
			// TODO collect culprits and return a list of them as per convention
			return round.WrapError(errors.New("de-commitment of v_j0..v_jt failed"), round.Parties().IDs()[j])
		}
		vj, err := crypto.UnFlattenECPoints(nil, flatVs)
		if err != nil {
			return round.WrapError(err, round.Parties().IDs()[j])
		}
		vjc[j] = vj

		// 5.
		Xj := round.temp.OldBigXj[j]
		if !vj[0].Equals(Xj) {
			// TODO collect culprits and return a list of them as per convention
			return round.WrapError(errors.New("v_j0 did not equal X_j"), round.Parties().IDs()[j])
		}

		// 6.
		sharej := round.temp.dgRound3ShareMessage[j]
		if ok := sharej.Share.Verify(round.NewThreshold(), vj); !ok {
			// TODO collect culprits and return a list of them as per convention
			return round.WrapError(errors.New("share from old committee did not pass Verify()"), round.Parties().IDs()[j])
		}

		// 7-10.
		iota := sharej.Share.Share
		for c := 0; c <= round.Threshold(); c++ { // P1..P_t+1. Ps are indexed from 0 here
			if j == c {
				continue
			}
			kc, kj := round.temp.OldKs[c], round.temp.OldKs[j]
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
	newKs := make([]*big.Int, 0, round.NewPartyCount())
	NewBigXj := make([]*crypto.ECPoint, round.NewPartyCount())
	for j := 0; j < round.NewPartyCount(); j++ {
		NewBigXj[j] = Vc[0]
		kj := round.NewParties().IDs()[j].Key
		newKs = append(newKs, kj)
		for c := 0; c < round.NewThreshold(); c++ {
			z := modQ.Exp(kj, big.NewInt(int64(c)))
			NewBigXj[j] = NewBigXj[j].Add(Vc[c].ScalarMult(z))
		}
	}

	// 21.
	// for this P: SAVE
	// - shareID
	// - the new X_i secret
	// - the new BigX_j = X_i*G
	round.save.ShareID = round.PartyID().Key
	round.save.Xi = newXi
	round.save.BigXj = NewBigXj
	round.save.Ks = newKs
	round.save.Index = i

	// TODO reconcile with other parties
	round.save.ECDSAPub = round.temp.dgRound1OldCommitteeCommitMessages[0].ECDSAPub

	// misc: build list of paillier public keys to save
	for j, msg := range round.temp.dgRound2PaillierPublicKeyMessage {
		if j == i {
			continue
		}
		round.save.PaillierPks[j] = msg.paillierPK
	}
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
