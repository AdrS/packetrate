package stream

import "math"

// Stores information pertaining to the computation of a statistic ex: min, max, mean, stdev
type Statistic interface {
	Update(sample float64)
	Result() float64
}

// Store minimum value in a stream
type Min struct {
	Min float64
}

func NewMin() *Min {
	return &Min{math.MaxFloat64}
}

func (s *Min) Update(sample float64) {
	if(sample < s.Min) {
		s.Min = sample
	}
}

func (s *Min) Result() float64 { return s.Min }

// Store maximum value in a stream
type Max struct {
	Max float64
}

func NewMax() *Max {
	return &Max{0}
}

func (s *Max) Update(sample float64) {
	if(sample > s.Max) {
		s.Max = sample
	}
}

func (s *Max) Result() float64 { return s.Max }

// Store sum of stream values
type Sum struct {
	Sum float64
}

func NewSum() *Sum {
	return &Sum{0}
}

func (s *Sum) Update(sample float64) {
	s.Sum += sample
}

func (s *Sum) Result() float64 { return s.Sum }
