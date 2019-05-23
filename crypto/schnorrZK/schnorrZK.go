package schnorrZK

import (
	"math/big"

	s256k1 "github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/sha3"

	"github.com/binance-chain/tss-lib/common/math"
)

var (
	EC *s256k1.KoblitzCurve
)

func init() {
	EC = s256k1.S256()
}

type ZKProof struct {
	E *big.Int
	S *big.Int
}

func ZKProve(u *big.Int) *ZKProof {
	r := math.GetRandomPositiveInt(EC.N)
	rGx, rGy := EC.ScalarBaseMult(r.Bytes())

	plain   := "BNC_PLAINTEXT"
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write([]byte(plain))
	eBytes  := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	s := new(big.Int).Mul(e, u)
	s  = new(big.Int).Add(r, s)
	s  = new(big.Int).Mod(s, EC.N)

	return &ZKProof{E: e, S: s}
}

func ZKVerify(uG []*big.Int, zkProof *ZKProof) bool {
	sGx, sGy := EC.ScalarBaseMult(zkProof.S.Bytes())

	minusE := new(big.Int).Mul(big.NewInt(-1), zkProof.E)
	minusE = new(big.Int).Mod(minusE, EC.N)

	eUx, eUy := EC.ScalarMult(uG[0], uG[1], minusE.Bytes())
	rGx, rGy := EC.Add(sGx, sGy, eUx, eUy)

	plain := "BNC_PLAINTEXT"
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write([]byte(plain))
	eBytes := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	if e.Cmp(zkProof.E) == 0 {
		return true
	} else {
		return false
	}
}
