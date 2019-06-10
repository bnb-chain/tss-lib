package primes

import (
	"math"
	"sort"
)

// Factors represents factors
type Factors struct {
	of   int64
	list []int64
	dict map[int64]int
}

// Factorize factorizes given number
func Factorize(num int64) *Factors {
	f := &Factors{of: num, list: []int64{}, dict: map[int64]int{}}
	//for _, prime := range Until(f.of).List() {
	for _, prime := range Globally.Until(f.of).List() {
		if f.of%prime == 0 {
			f.add(prime)
		}
	}
	return f
}

func (f *Factors) add(factor int64) {
	f.list = append(f.list, factor)
	f.dict[factor] = f.HasPowersOf(factor)
}

func (f *Factors) HasPowersOf(factor int64) int {
	if f.of%factor != 0 {
		return 0
	}
	if p, alreadyHas := f.dict[factor]; alreadyHas {
		return p
	}
	res := 1
	for i := 0; ; i++ {
		pow := math.Pow(float64(factor), float64(i))
		if f.of < int64(pow) {
			break
		}
		if f.of%int64(pow) == 0 {
			res = i
		}
	}
	return res
}

// List returns distict list of factors
func (f *Factors) List() []int64 {
	return f.list
}

// All returns all factors
func (f *Factors) All() []int64 {
	res := []int64{}
	for _, n := range f.list {
		for i := 0; i < f.dict[n]; i++ {
			res = append(res, n)
		}
	}
	return res
}

// Powers returns dict formatted factors
func (f *Factors) Powers() map[int64]int {
	return f.dict
}

// Commons returns common factors of two numbers
func Commons(a, b *Factors) *Factors {
	dest := map[int64]int{}
	for n, p := range a.Powers() {
		if bp := b.HasPowersOf(n); bp != 0 {
			if bp < p {
				dest[n] = bp
			} else {
				dest[n] = p
			}
		}
	}
	return generateFactorsByDict(dest)
}

func generateFactorsByDict(dict map[int64]int) *Factors {
	f := new(Factors)
	f.dict = dict
	return f.recover()
}

func (f *Factors) recover() *Factors {
	var dest int64
	for n, p := range f.dict {
		f.list = append(f.list, n)
		dest += int64(math.Floor(math.Pow(float64(n), float64(p))))
	}
	sort.Sort(sorter(f.list))
	f.of = dest
	return f
}

type sorter []int64

func (s sorter) Len() int {
	return len(s)
}
func (s sorter) Less(i, j int) bool {
	return s[i] < s[j]
}
func (s sorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
