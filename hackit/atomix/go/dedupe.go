package main

import (
	"sync"
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

func (t *Throttler) Wait() {
	if t == nil || t.disabled || t.delay <= 0 {
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
