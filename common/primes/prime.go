package primes

// Primes represents prime numbers
type Primes struct {
	target     int64
	dictionary map[int64]bool
	list       []int64
}

// Until finds prime numbers until specified number.
func Until(n int64) *Primes {

	if known := Globally.Know(n); known != nil {
		return known
	}

	p := initializeUntil(n)

	var i int64 = 2

	for ; i <= p.target; i++ {
		if p.knows(i) {
			continue // needless to evaluate.
		}
		if p.canDivideByKnownPrimeNumbers(i) {
			continue // it's not prime number.
		}
		// it's prime number,
		// and multiples of this number are no longer needless to be eveluated
		p.add(i)
	}

	Globally.Learn(p)

	return p
}

// initializeUntil makes `Primes` instance,
// and init **all possibile primes** dictonary in itself.
// Initially, numbers in the dictionary are all marked as `false`,
// as meaning "it's not prime".
func initializeUntil(n int64) *Primes {
	p := new(Primes)
	p.target = n
	p.dictionary = map[int64]bool{}

	for i := 2; int64(i) <= p.target; i++ {
		p.dictionary[int64(i)] = false
	}
	return p
}

// canDivideByKnownPrimeNumbers checks the given number can devide
// by known prime numbers of this `Primes`.
func (p *Primes) canDivideByKnownPrimeNumbers(i int64) bool {
	for _, n := range p.list {
		if i%n == 0 {
			// this given number can be devided by already known prime numbers.
			return true
		}
	}
	// this given number can NOT be devided by already known prime numbers.
	return false
}

// knows returns whether this Primes already recognize that
// the given number and multiples of that as known prime numbers or not,
// by referencing it's dictionary.
func (p *Primes) knows(i int64) bool {
	marked, ok := p.dictionary[i]
	if !ok {
		return false
	}
	return marked
}

// add adds given number in dictionary and marks it as a known prime number.
// Moreover, the multiples of the given number should be known numbers which
// is no longer need to be calculated hereafter.
func (p *Primes) add(i int64) {
	// register this number
	p.list = append(p.list, i)
	// mark this number
	p.dictionary[i] = true
	// mark multiples of this number
	// to make better `Sieve of Eratosthenes`
	for j := 2; i*int64(j) < p.target; j++ {
		p.dictionary[i*int64(j)] = true
	}
}

// List returns all found primes as a slice.
func (p *Primes) List() []int64 {
	return p.list
}
