package commitments

import (
	"errors"
	"math/big"
)

type builder struct {
	parts [][]*big.Int
}

func NewBuilder() *builder {
	b := new(builder)
	b.parts = make([][]*big.Int, 0, 5)
	return b
}

func (b *builder) Parts() [][]*big.Int {
	return b.parts[:]
}

func (b *builder) AddPart(part []*big.Int) *builder {
	b.parts = append(b.parts, part)
	return b
}

func (b *builder) Secrets() []*big.Int {
	secretsLen := 0
	for _, p := range b.parts {
		secretsLen += 1 + len(p) // +1 to accommodate length prefix element
	}
	secrets := make([]*big.Int, 0, secretsLen)
	for _, p := range b.parts {
		secrets = append(secrets, big.NewInt(int64(len(p))))
		secrets = append(secrets, p...)
	}
	return secrets
}

func ParseSecrets(secrets []*big.Int) ([][]*big.Int, error) {
	if secrets == nil || len(secrets) < 2 {
		return nil, errors.New("ParseSecrets: secrets == nil or is too small")
	}
	var el, nextPartLen int64
	parts := make([][]*big.Int, 0, 5)
	isLenEl := true // are we looking at a length prefix element? (first one is)
	inLen := int64(len(secrets))
	for el < inLen {
		if isLenEl {
			nextPartLen = secrets[el].Int64()
			el += 1
		} else {
			if inLen < el+nextPartLen {
				return nil, errors.New("ParseSecrets: not enough data to consume stated data length")
			}
			part := secrets[el : el+nextPartLen]
			parts = append(parts, part)
			el += nextPartLen
		}
		isLenEl = !isLenEl
	}
	return parts, nil
}
