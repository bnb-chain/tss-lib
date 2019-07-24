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
		name   string
		fields fields
		want   []*big.Int
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
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &builder{
				parts: tt.fields.parts,
			}
			if got := b.Secrets(); !reflect.DeepEqual(got, tt.want) {
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
		wantErr: false,
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
		wantErr: false,
	}, {
		name: "Errors: Invalid input - too short",
		args: args{
			[]*big.Int{
				one, // just the length prefix, no content!
			},
		},
		want:    nil,
		wantErr: true,
	}, {
		name: "Errors: Invalid input - insufficient data",
		args: args{
			[]*big.Int{
				one, one,
				two, one, // one element is missing
			},
		},
		want:    nil,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSecrets(tt.args.secrets)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSecrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("ParseSecrets() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
