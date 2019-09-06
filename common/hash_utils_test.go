package common

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/binance-chain/tss-lib/common/random"
)

func TestRejectionSample(t *testing.T) {
	curveQ  := random.GetRandomPrimeInt(256)
	randomQ := random.MustGetRandomInt(64)
	hash := SHA512_256iOne(big.NewInt(123))
	rs1 := RejectionSample(curveQ, hash)
	rs2 := RejectionSample(randomQ, hash)
	rs3 := RejectionSample(random.MustGetRandomInt(64), hash)
	type args struct {
		q     *big.Int
		eHash *big.Int
	}
	tests := []struct {
		name       string
		args       args
		want       *big.Int
		wantBitLen int
		notEqual   bool
	}{{
		name: "happy path with curve order",
		args: args{curveQ, hash},
		want: rs1,
		wantBitLen: 256,
	}, {
		name: "happy path with random 64-bit int",
		args: args{randomQ, hash},
		want: rs2,
		wantBitLen: 64,
	}, {
		name: "inequality with different input",
		args: args{randomQ, hash},
		want: rs3,
		wantBitLen: 64,
		notEqual: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RejectionSample(tt.args.q, tt.args.eHash)
			if !tt.notEqual && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RejectionSample() = %v, want %v", got, tt.want)
			}
			if tt.wantBitLen < got.BitLen() { // leading zeros not counted
				t.Errorf("RejectionSample() = bitlen %d, want %d", got.BitLen(), tt.wantBitLen)
			}
		})
	}
}
