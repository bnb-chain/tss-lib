package primes

import (
	"fmt"
	"regexp"
	"strconv"
)

// Fraction represents fraction
type Fraction struct {
	numerator   int64
	denominator int64
	commons     *Factors
	before      *Fraction
}

var fractionLikeExp = regexp.MustCompile("^([0-9]+)/([0-9]+)$")

// ParseFractionString parses and initializes Fraction from string
func ParseFractionString(fractionLike string) (*Fraction, error) {
	f := new(Fraction)
	matches := fractionLikeExp.FindStringSubmatch(fractionLike)
	if len(matches) != 3 {
		return f, fmt.Errorf("failed to parse string `%s` to fraction", fractionLike)
	}
	num, err := strconv.Atoi(matches[1])
	if err != nil {
		return f, err
	}
	den, err := strconv.Atoi(matches[2])
	if err != nil {
		return f, err
	}
	return Fractionize(int64(num), int64(den)), nil
}

// Fractionize ...
func Fractionize(num, den int64) *Fraction {
	f := new(Fraction)
	f.numerator = num
	f.denominator = den

	f.commons = Commons(
		Factorize(f.numerator),
		Factorize(f.denominator),
	)

	return f
}

// Reduce recuces this fraction
func (fr *Fraction) Reduce(times int) *Fraction {
	if times == 0 {
		return fr
	}
	if len(fr.commons.All()) == 0 {
		return fr
	}
	c := fr.commons.All()[0]
	next := Fractionize(fr.numerator/c, fr.denominator/c)
	next.before = fr
	times--
	return next.Reduce(times)
}

// String ...
func (fr *Fraction) String() string {
	return fmt.Sprintf("%d/%d", fr.numerator, fr.denominator)
}
