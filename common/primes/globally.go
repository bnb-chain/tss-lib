package primes

import (
	"container/list"
)

type cache struct {
	store map[int64]*Primes
	list  *list.List
}

// Globally ...
var Globally = &cache{
	store: map[int64]*Primes{},
	list:  list.New(),
}

func (c *cache) Clear() {
	c.store = map[int64]*Primes{}
	c.list = list.New()
}

func (c *cache) Know(target int64) *Primes {
	if p, ok := c.store[target]; ok {
		return p
	}
	return nil
}

func (c *cache) Learn(p *Primes) *cache {
	c.store[p.target] = p
	if c.list.Len() == 0 {
		c.list.PushFront(p)
		return c
	}
	for e := c.list.Front(); e != nil; e = e.Next() {
		if e.Value.(*Primes).target > p.target {
			c.list.InsertBefore(p, e)
			return c
		}
	}
	c.list.PushBack(p)
	return c
}

func (c *cache) Until(n int64) *Primes {

	base := c.Persist(n)

	i := base.target
	if i == 1 {
		i = 2
	}
	p := extends(base, n)

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

func extends(base *Primes, target int64) *Primes {
	p := new(Primes)
	p.target = target
	p.dictionary = base.dictionary
	p.list = base.list
	return p
}

func (c *cache) Persist(target int64) *Primes {
	if c.list.Len() == 0 {
		return Until(2)
	}
	max := c.list.Back().Value.(*Primes)
	fabricated := &Primes{target: target, dictionary: map[int64]bool{}, list: []int64{}}
	for _, n := range max.List() {
		if n < target {
			fabricated.add(n)
		}
	}
	return fabricated
}
