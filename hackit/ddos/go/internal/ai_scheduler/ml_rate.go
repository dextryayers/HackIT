package ai_scheduler

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	targetRTT = 50 * time.Millisecond
	kp        = 1.5
	ki        = 0.2
	kd        = 0.5
)

type AdaptiveRate struct {
	currentRate  int64
	minRate      int64
	maxRate      int64
	rttSamples   [10]time.Duration
	sampleIndex  int
	mu           sync.Mutex
	prevError    float64
	integral     float64
}

func NewAdaptiveRate(initial, min, max int) *AdaptiveRate {
	return &AdaptiveRate{
		currentRate: int64(initial),
		minRate:     int64(min),
		maxRate:     int64(max),
	}
}

func (a *AdaptiveRate) RecordRTT(rtt time.Duration) {
	a.mu.Lock()
	a.rttSamples[a.sampleIndex%10] = rtt
	a.sampleIndex++
	a.mu.Unlock()
}

func (a *AdaptiveRate) ComputeRate() int {
	a.mu.Lock()

	n := a.sampleIndex
	if n > 10 {
		n = 10
	}

	var avg time.Duration
	if n > 0 {
		var sum time.Duration
		start := a.sampleIndex - n
		for i := 0; i < n; i++ {
			idx := (start + i) % 10
			if idx < 0 {
				idx += 10
			}
			sum += a.rttSamples[idx]
		}
		avg = sum / time.Duration(n)
	}

	current := float64(atomic.LoadInt64(&a.currentRate))

	var rate int
	if avg == 0 {
		rate = int(current)
	} else {
		err := float64(targetRTT - avg)

		p := kp * err
		a.integral += ki * err
		d := kd * (err - a.prevError)

		delta := p + a.integral + d
		a.prevError = err

		rate = int(math.Round(current + delta))
	}

	a.mu.Unlock()

	if rate < int(a.minRate) {
		rate = int(a.minRate)
	}
	if rate > int(a.maxRate) {
		rate = int(a.maxRate)
	}

	atomic.StoreInt64(&a.currentRate, int64(rate))
	return rate
}

func (a *AdaptiveRate) CurrentRate() int {
	return int(atomic.LoadInt64(&a.currentRate))
}

func (a *AdaptiveRate) SetRate(rate int) {
	atomic.StoreInt64(&a.currentRate, int64(rate))
}
