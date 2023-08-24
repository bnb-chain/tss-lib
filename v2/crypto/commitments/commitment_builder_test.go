// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package commitments

import (
	"math/big"
	"reflect"
	"testing"
)

var (
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
)

func Test_builder_Secrets(t *testing.T) {
	type fields struct {
		parts [][]*big.Int
	}
	tests := []struct {
		name    string
		fields  fields
		want    []*big.Int
		wantErr bool
	}{{
		name: "Happy path: Single part",
		fields: fields{[][]*big.Int{
			{one},
		}},
		want: []*big.Int{
			one, one,
		},
	}, {
		name: "Happy path: Multiple parts",
		fields: fields{[][]*big.Int{
			{one},
			{one, two},
			{one, two, three},
		}},
		want: []*big.Int{
			one, one,
			two, one, two,
			three, one, two, three,
		},
	}, {
		name: "Errors: Too many parts - max is 3",
		fields: fields{[][]*big.Int{
			{one},
			{one},
			{one, two},
			{one, two, three},
		}},
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &builder{
				parts: tt.fields.parts,
			}
			got, err := b.Secrets()
			if (err != nil) != tt.wantErr {
				t.Errorf("builder.Secrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("builder.Secrets() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSecrets(t *testing.T) {
	type args struct {
		secrets []*big.Int
	}
	tests := []struct {
		name    string
		args    args
		want    [][]*big.Int
		wantErr bool
	}{{
		name: "Happy path: Single part",
		args: args{
			[]*big.Int{
				one, one,
			},
		},
		want: [][]*big.Int{
			{one},
		},
	}, {
		name: "Happy path: Multiple parts",
		args: args{
			[]*big.Int{
				// one element: one
				one, one,
				// two elements: one, two
				two, one, two,
				// three elements: one, two three
				three, one, two, three,
			},
		},
		want: [][]*big.Int{
			{one},
			{one, two},
			{one, two, three},
		},
	}, {
		name: "Errors: Invalid input - too short",
		args: args{
			[]*big.Int{
				one, // just the length prefix, no content!
			},
		},
		wantErr: true,
	}, {
		name: "Errors: Invalid input - insufficient data",
		args: args{
			[]*big.Int{
				one, one,
				two, one, // one element is missing
			},
		},
		wantErr: true,
	}, {
		name: "Errors: Too many parts - max is 3",
		args: args{
			[]*big.Int{
				one, one,
				one, one,
				one, one,
				one, one,
			},
		},
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSecrets(tt.args.secrets)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSecrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSecrets() = %v, want %v", got, tt.want)
			}
		})
	}
}
