package regroup

import (
	"errors"
	"math/big"

	errors2 "github.com/pkg/errors"

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

	// 1-3. verify paillier key proofs
	culprits := make([]*tss.PartyID, 0, len(round.NewParties().IDs())) // who caused the error(s)
	for _, msg := range round.temp.dgRound2PaillierPublicKeyMessage {
		proof := msg.PaillierPf
		if ok, err := proof.Verify(msg.PaillierPK.N, msg.GetFrom().Key, round.save.ECDSAPub); !ok || err != nil {
			culprits = append(culprits, msg.GetFrom())
			common.Logger.Warningf("paillier verify failed for party %s", msg.GetFrom())
			continue
		}
		common.Logger.Debugf("paillier verify passed for party %s", msg.GetFrom())
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("paillier verify failed"), culprits...)
	}

	// save NTilde_j, h1_j, h2_j received in NewCommitteeStep1 here
	for j, msg := range round.temp.dgRound2PaillierPublicKeyMessage {
		if j == i {
			continue
		}
		round.save.NTildej[j] = msg.NTildei
		round.save.H1j[j], round.save.H2j[j] = msg.H1i, msg.H2i
	}

	// 4.
	newXi := big.NewInt(0)

	// 5-9.
	modQ := common.ModInt(tss.EC().Params().N)
	vjc := make([][]*crypto.ECPoint, round.Threshold()+1)
	for j := 0; j <= round.Threshold(); j++ { // P1..P_t+1. Ps are indexed from 0 here
		// 6-7.
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

		// 6. unpack flat "v" commitment content
		vCmtDeCmt := commitments.HashCommitDecommit{C: vCj, D: vDj}
		ok, flatVs := vCmtDeCmt.DeCommit()
		if !ok || len(flatVs) != (round.NewThreshold()+1)*2 { // they're points so * 2
			// TODO collect culprits and return a list of them as per convention
			return round.WrapError(errors.New("de-commitment of v_j0..v_jt failed"), round.Parties().IDs()[j])
		}
		vj, err := crypto.UnFlattenECPoints(tss.EC(), flatVs)
		if err != nil {
			return round.WrapError(err, round.Parties().IDs()[j])
		}
		vjc[j] = vj

		// 8.
		sharej := round.temp.dgRound3ShareMessage[j]
		if ok := sharej.Share.Verify(round.NewThreshold(), vj); !ok {
			// TODO collect culprits and return a list of them as per convention
			return round.WrapError(errors.New("share from old committee did not pass Verify()"), round.Parties().IDs()[j])
		}

		// 9.
		newXi = new(big.Int).Add(newXi, sharej.Share.Share)
	}

	// 10-13.
	var err error
	Vc := make([]*crypto.ECPoint, round.NewThreshold()+1)
	for c := 0; c <= round.NewThreshold(); c++ {
		Vc[c] = vjc[0][c]
		for j := 1; j <= round.Threshold(); j++ {
			Vc[c], err = Vc[c].Add(vjc[j][c])
			if err != nil {
				return round.WrapError(errors2.Wrapf(err, "Vc[c].Add(vjc[j][c])"))
			}
		}
	}

	// 14.
	if !Vc[0].Equals(round.save.ECDSAPub) {
		return round.WrapError(errors.New("assertion failed: V_0 != y"), round.PartyID())
	}

	// 15-19.
	newKs := make([]*big.Int, 0, round.NewPartyCount())
	NewBigXj := make([]*crypto.ECPoint, round.NewPartyCount())
	culprits = make([]*tss.PartyID, 0, round.NewPartyCount()) // who caused the error(s)
	for j := 0; j < round.NewPartyCount(); j++ {
		Pj := round.NewParties().IDs()[j]
		kj := Pj.Key
		newBigXj := Vc[0]
		newKs = append(newKs, kj)
		z := new(big.Int).SetInt64(int64(1))
		for c := 1; c <= round.NewThreshold(); c++ {
			z = modQ.Mul(z, kj)
			newBigXj, err = newBigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				culprits = append(culprits, Pj)
			}
		}
		NewBigXj[j] = newBigXj
	}
	if len(culprits) > 0 {
		return round.WrapError(errors2.Wrapf(err, "newBigXj.Add(Vc[c].ScalarMult(z))"), culprits...)
	}
	round.save.BigXj = NewBigXj

	// 21.
	// for this P: SAVE other data
	round.save.ShareID = round.PartyID().Key
	round.save.Xi = newXi
	round.save.Ks = newKs

	// misc: build list of paillier public keys to save
	for j, msg := range round.temp.dgRound2PaillierPublicKeyMessage {
		if j == i {
			continue
		}
		round.save.PaillierPks[j] = msg.PaillierPK
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
