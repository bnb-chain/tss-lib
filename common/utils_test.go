package common

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/tss"
)

func TestRejectionSample(t *testing.T) {
	curveQ  := tss.EC().Params().N
	randomQ := random.MustGetRandomInt(64)
	hash, _ := SHA512_256i(big.NewInt(123))
	rs1, _ := RejectionSample(curveQ, hash)
	rs2, _ := RejectionSample(randomQ, hash)
	rs3, _ := RejectionSample(random.MustGetRandomInt(64), hash)
	type args struct {
		q     *big.Int
		eHash *big.Int
	}
	tests := []struct {
		name       string
		args       args
		want       *big.Int
		wantErr    bool
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
			got, err := RejectionSample(tt.args.q, tt.args.eHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("RejectionSample() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.notEqual && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RejectionSample() = %v, want %v", got, tt.want)
			}
			if tt.wantBitLen < got.BitLen() { // leading zeros not counted
				t.Errorf("RejectionSample() = bitlen %d, want %d", got.BitLen(), tt.wantBitLen)
			}
		})
	}
}
