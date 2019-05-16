package math_test

import (
	"testing"

	"tss-lib/common/math"
)

const (
	randomIntLength = 1024
)

func TestGetRandomInt(t *testing.T) {
	rndInt := math.GetRandomInt(randomIntLength)
	t.Log(rndInt)
}

func TestGetRandomPositiveInt(t *testing.T) {
	rndInt := math.GetRandomInt(randomIntLength)
	t.Log(rndInt)
	rndIntZn := math.GetRandomPositiveInt(rndInt)
	t.Log(rndIntZn)
}

func TestGetRandomPositiveIntStar(t *testing.T) {
	rndInt := math.GetRandomInt(randomIntLength)
	t.Log(rndInt)
	rndIntZnStar := math.GetRandomPositiveIntStar(rndInt)
	t.Log(rndIntZnStar)
}

func TestGetRandomPrimeInt(t *testing.T) {
	primeInt := math.GetRandomPrimeInt(randomIntLength)
	t.Log(primeInt)
}
