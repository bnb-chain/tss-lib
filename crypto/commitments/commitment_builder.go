package commitments

import (
	"errors"
	"fmt"
	"math/big"
)

const (
	MaxParts    = 3
	MaxPartSize = int64(1 * 1024 * 1024) // 1 MB - rather liberal
)

type builder struct {
	parts [][]*big.Int
}

func NewBuilder() *builder {
	b := new(builder)
	b.parts = make([][]*big.Int, 0, MaxParts)
	return b
}

func (b *builder) Parts() [][]*big.Int {
	return b.parts[:]
}

func (b *builder) AddPart(part []*big.Int) *builder {
	b.parts = append(b.parts, part[:])
	return b
}

func (b *builder) Secrets() ([]*big.Int, error) {
	secretsLen := 0
	if len(b.parts) > MaxParts {
		return nil, fmt.Errorf("builder.Secrets: too many commitment parts provided: got %d, max %d", len(b.parts), MaxParts)
	}
	for _, p := range b.parts {
		secretsLen += 1 + len(p) // +1 to accommodate length prefix element
	}
	secrets := make([]*big.Int, 0, secretsLen)
	for i, p := range b.parts {
		partLen := int64(len(p))
		if MaxPartSize < partLen {
			return nil, fmt.Errorf("builder.Secrets: commitment part too large: part %d, size %d", i, partLen)
		}
		secrets = append(secrets, big.NewInt(partLen))
		secrets = append(secrets, p...)
	}
	return secrets, nil
}

func ParseSecrets(secrets []*big.Int) ([][]*big.Int, error) {
	if secrets == nil || len(secrets) < 2 {
		return nil, errors.New("ParseSecrets: secrets == nil or is too small")
	}
	var el, nextPartLen int64
	parts := make([][]*big.Int, 0, MaxParts)
	isLenEl := true // are we looking at a length prefix element? (first one is)
	inLen := int64(len(secrets))
	for el < inLen {
		if el < 0 {
			return nil, errors.New("ParseSecrets: `el` overflow")
		}
		if isLenEl {
			nextPartLen = secrets[el].Int64()
			if MaxPartSize < nextPartLen {
				return nil, fmt.Errorf("ParseSecrets: commitment part too large: part %d, size %d", len(parts), nextPartLen)
			}
			el += 1
		} else {
			if MaxParts <= len(parts) {
				return nil, fmt.Errorf("ParseSecrets: commitment has too many parts: part %d, max %d", len(parts), MaxParts)
			}
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
