package main

import (
	"sync"
	"time"
)

type TokenBucket struct {
	rate       float64
	capacity   float64
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

type RateLimiter struct {
	buckets   map[string]*TokenBucket
	defaultR  float64
	defaultC  float64
	mu        sync.RWMutex
}

func NewRateLimiter(ratePerSec, burst int) *RateLimiter {
	r := float64(ratePerSec)
	c := float64(burst)
	if r <= 0 { r = 1000 }
	if c <= 0 { c = r }
	return &RateLimiter{
		buckets:  make(map[string]*TokenBucket),
		defaultR: r,
		defaultC: c,
	}
}

func (rl *RateLimiter) getBucket(key string) *TokenBucket {
	rl.mu.RLock()
	b, ok := rl.buckets[key]
	rl.mu.RUnlock()
	if ok { return b }

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if b, ok := rl.buckets[key]; ok { return b }
	b = &TokenBucket{
		rate:       rl.defaultR,
		capacity:   rl.defaultC,
		tokens:     rl.defaultC,
		lastRefill: time.Now(),
	}
	rl.buckets[key] = b
	return b
}

func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastRefill = now
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

func (tb *TokenBucket) Wait() time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	if tb.tokens >= 1 {
		tb.tokens--
		return 0
	}
	needed := 1 - tb.tokens
	wait := time.Duration(needed/tb.rate) * time.Second
	return wait
}

type AdaptiveRateLimiter struct {
	rl         *RateLimiter
	successes  int64
	failures   int64
	lastAdjust time.Time
	mu         sync.Mutex
}

func NewAdaptiveRateLimiter(baseRate, burst int) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		rl: NewRateLimiter(baseRate, burst),
	}
}

func (arl *AdaptiveRateLimiter) Allow(key string) bool {
	arl.mu.Lock()
	if time.Since(arl.lastAdjust) > 10*time.Second {
		total := arl.successes + arl.failures
		if total > 10 {
			ratio := float64(arl.failures) / float64(total)
			if ratio > 0.3 {
				arl.rl.defaultR *= 0.8
			} else if ratio < 0.05 && arl.rl.defaultR < 5000 {
				arl.rl.defaultR *= 1.2
			}
		}
		arl.successes = 0
		arl.failures = 0
		arl.lastAdjust = time.Now()
	}
	arl.mu.Unlock()
	return arl.rl.getBucket(key).Allow()
}
