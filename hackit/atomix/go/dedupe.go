package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type Deduplicator struct {
	seen map[string]time.Time
	mu   sync.RWMutex
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]time.Time),
	}
}

func (d *Deduplicator) IsDuplicate(templateID, url, matcherName string) bool {
	key := templateID + "|" + url + "|" + matcherName
	d.mu.RLock()
	_, exists := d.seen[key]
	d.mu.RUnlock()
	return exists
}

func (d *Deduplicator) MarkSeen(templateID, url, matcherName string) {
	key := templateID + "|" + url + "|" + matcherName
	d.mu.Lock()
	d.seen[key] = time.Now()
	d.mu.Unlock()
}

func (d *Deduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.seen)
}

func (d *Deduplicator) Clear() {
	d.mu.Lock()
	d.seen = make(map[string]time.Time)
	d.mu.Unlock()
}

type Throttler struct {
	delay    time.Duration
	lastSent time.Time
	mu       sync.Mutex
	disabled bool
	// Adaptive mode: lock-free per-request pacing whose delay follows
	// the observed error rate. Zero delay means full speed.
	adaptive bool
	pacing   atomic.Int64 // nanoseconds
	adaptMu  sync.Mutex
	window   int
	winErrs  int
}

func NewThrottler(delayMs int) *Throttler {
	if delayMs <= 0 {
		return &Throttler{disabled: true}
	}
	return &Throttler{
		delay: time.Duration(delayMs) * time.Millisecond,
	}
}

// NewThrottlerFromRPS builds a throttler from requests-per-second.
// rps <= 0 means disabled (no artificial delay).
func NewThrottlerFromRPS(rps int) *Throttler {
	if rps <= 0 {
		return &Throttler{disabled: true}
	}
	intervalMs := 1000 / rps
	if intervalMs < 1 {
		intervalMs = 1
	}
	return &Throttler{delay: time.Duration(intervalMs) * time.Millisecond}
}

// NewAdaptiveThrottler starts at full speed and backs off only when errors
// pile up. startRPS > 0 seeds the initial pacing instead of zero.
func NewAdaptiveThrottler(startRPS int) *Throttler {
	t := &Throttler{adaptive: true}
	if startRPS > 0 {
		ms := 1000 / startRPS
		if ms < 1 {
			ms = 1
		}
		t.pacing.Store(int64(time.Duration(ms) * time.Millisecond))
	}
	return t
}

func (t *Throttler) Wait() {
	if t == nil || t.disabled {
		return
	}
	if t.adaptive {
		if d := t.pacing.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}
		return
	}
	if t.delay <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	elapsed := time.Since(t.lastSent)
	if elapsed < t.delay {
		time.Sleep(t.delay - elapsed)
	}
	t.lastSent = time.Now()
}

// Adapt feeds one request outcome back. Every 20 samples the pacing is
// retuned: error storms back off up to 500ms, clean runs speed back to 0.
func (t *Throttler) Adapt(ok bool) {
	if t == nil || !t.adaptive {
		return
	}
	t.adaptMu.Lock()
	defer t.adaptMu.Unlock()
	t.window++
	if !ok {
		t.winErrs++
	}
	if t.window < 20 {
		return
	}
	ratio := float64(t.winErrs) / float64(t.window)
	cur := t.pacing.Load()
	switch {
	case ratio > 0.25:
		cur = cur*2 + int64(5*time.Millisecond)
		if cur > int64(500*time.Millisecond) {
			cur = int64(500 * time.Millisecond)
		}
		t.pacing.Store(cur)
	case ratio < 0.05 && cur > 0:
		cur -= int64(5 * time.Millisecond)
		if cur < 0 {
			cur = 0
		}
		t.pacing.Store(cur)
	}
	t.window = 0
	t.winErrs = 0
}
