package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// latencyTracker keeps a small rolling window of successful request latencies.
// A slow-but-alive server (6s here) is not a dead server: the per-attempt
// deadline is derived from the measured p95 so the engine stops reporting a
// false TIMEOUT on every path and starts actually reading the responses.
type latencyTracker struct {
	mu      sync.Mutex
	samples []time.Duration
	cap     int
}

var latency = &latencyTracker{cap: 64}

func (l *latencyTracker) record(d time.Duration) {
	if d <= 0 {
		return
	}
	l.mu.Lock()
	l.samples = append(l.samples, d)
	if len(l.samples) > l.cap {
		l.samples = l.samples[len(l.samples)-l.cap:]
	}
	l.mu.Unlock()
}

func (l *latencyTracker) p95() time.Duration {
	l.mu.Lock()
	if len(l.samples) == 0 {
		l.mu.Unlock()
		return 0
	}
	s := make([]time.Duration, len(l.samples))
	copy(s, l.samples)
	l.mu.Unlock()

	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	idx := (len(s) * 95) / 100
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

// adaptiveTimeout returns the per-attempt deadline. It never drops below the
// operator's -timeout value, and extends up to 4x when the measured p95 shows
// the target is slow rather than unreachable.
func adaptiveTimeout(config *ScanConfig) time.Duration {
	base := time.Duration(config.Timeout) * time.Second
	if base <= 0 {
		base = 5 * time.Second
	}
	want := base
	if p95 := latency.p95(); p95 > 0 {
		want = time.Duration(float64(p95) * 2.5)
	}
	if want < base {
		want = base
	}
	if maxT := base * 4; want > maxT {
		want = maxT
	}
	return want
}

// isTimeoutErr reports a deadline/transient network failure, which is worth
// another attempt. DNS and refused connections are not.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if err == context.DeadlineExceeded {
		return true
	}
	if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
		return true
	}
	return false
}

// Timeout streak: a run of consecutive timeouts means the target is
// overloaded, so the whole scan throttles rather than hammering it.
var timeoutStreak int32

func noteTimeout() {
	n := atomic.AddInt32(&timeoutStreak, 1)
	if n > 4 {
		n = 4
	}
	if n < 4 {
		return
	}
	until := time.Now().Add(400 * time.Millisecond).UnixNano()
	for {
		old := atomic.LoadInt64(&backoffUntilNano)
		if until <= old {
			return
		}
		if atomic.CompareAndSwapInt64(&backoffUntilNano, old, until) {
			return
		}
	}
}

func clearTimeout() {
	atomic.StoreInt32(&timeoutStreak, 0)
}

// effectiveRetries: a timeout is cheap to retry (the path is otherwise lost),
// so timeouts get more attempts than a hard connection failure.
func effectiveRetries(config *ScanConfig, timedOut bool) int {
	if !timedOut {
		return config.Retries
	}
	n := config.Retries + 2
	if n > 4 {
		n = 4
	}
	return n
}
