package crypto_test

import (
	"math/big"
	"reflect"
	"testing"

	. "github.com/binance-chain/tss-lib/crypto"
)

func TestFlattenECPoints(t *testing.T) {
	type args struct {
		in []*ECPoint
	}
	tests := []struct {
		name    string
		args    args
		want    []*big.Int
		wantErr bool
	}{{
		name: "flatten with 2 points (happy)",
		args: args{[]*ECPoint{
			{big.NewInt(1), big.NewInt(2)},
			{big.NewInt(3), big.NewInt(4)}},
		},
		want: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)},
	}, {
		name: "flatten with nil point (expects err)",
		args: args{[]*ECPoint{
			{big.NewInt(1), big.NewInt(2)},
			nil,
			{big.NewInt(3), big.NewInt(4)}},
		},
		want: nil,
		wantErr: true,
	}, {
		name: "flatten with nil coordinate (expects err)",
		args: args{[]*ECPoint{
			{big.NewInt(1), big.NewInt(2)},
			{nil, big.NewInt(4)}},
		},
		want: nil,
		wantErr: true,
	}, {
		name: "flatten with nil `in` slice",
		args: args{nil},
		want: nil,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FlattenECPoints(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("FlattenECPoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FlattenECPoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnFlattenECPoints(t *testing.T) {
	type args struct {
		in []*big.Int
	}
	tests := []struct {
		name    string
		args    args
		want    []*ECPoint
		wantErr bool
	}{{
		name: "un-flatten 2 points (happy)",
		args: args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}},
		want: []*ECPoint{
			{big.NewInt(1), big.NewInt(2)},
			{big.NewInt(3), big.NewInt(4)}},
	}, {
		name: "un-flatten uneven len(points) (expects err)",
		args: args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}},
		want: nil,
		wantErr: true,
	}, {
		name: "un-flatten with nil coordinate (expects err)",
		args: args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), nil}},
		want: nil,
		wantErr: true,
	}, {
		name: "flatten with nil `in` slice",
		args: args{nil},
		want: nil,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnFlattenECPoints(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnFlattenECPoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnFlattenECPoints() = %v, want %v", got, tt.want)
			}
		})
	}
}
