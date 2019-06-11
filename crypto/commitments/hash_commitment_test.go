package commitments_test

import (
	"math/big"
	"reflect"
	"testing"

	. "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/stretchr/testify/assert"
)

func TestFlattenPointsForCommit(t *testing.T) {
	type args struct {
		in [][]*big.Int
	}
	tests := []struct {
		name    string
		args    args
		want    []*big.Int
		wantErr bool
	}{{
		name: "test flatten with 2 points",
		args: args{[][]*big.Int{
			{big.NewInt(1), big.NewInt(2)},
			{big.NewInt(3), big.NewInt(4)}},
		},
		want: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FlattenPointsForCommit(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("FlattenPointsForCommit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FlattenPointsForCommit() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnFlattenPointsAfterDecommit(t *testing.T) {
	type args struct {
		in []*big.Int
	}
	tests := []struct {
		name    string
		args    args
		want    [][]*big.Int
		wantErr bool
	}{{
		name: "test un-flatten 2 points",
		args: args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}},
		want: [][]*big.Int{
			{big.NewInt(1), big.NewInt(2)},
			{big.NewInt(3), big.NewInt(4)}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnFlattenPointsAfterDecommit(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnFlattenPointsAfterDecommit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnFlattenPointsAfterDecommit() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommit(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment, err := NewHashCommitment(zero, one)
	assert.NoError(t, err)

	t.Log(commitment.C)
	t.Log(commitment.D)
}

func TestVerify(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment, err := NewHashCommitment(zero, one)
	assert.NoError(t, err)

	pass, err := commitment.Verify()
	assert.NoError(t, err)

	t.Log(commitment.C)
	t.Log(commitment.D)

	assert.True(t, pass, "must pass")
}

func TestDeCommit(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment, err := NewHashCommitment(zero, one)
	assert.NoError(t, err)

	pass, secrets, err := commitment.DeCommit()
	assert.NoError(t, err)

	t.Log(commitment.D)
	t.Log(commitment.C)

	assert.True(t, pass, "must pass")

	assert.NotZero(t, len(secrets), "len(secrets) must be non-zero")
}
