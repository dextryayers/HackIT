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
}

func NewThrottler(delayMs int) *Throttler {
	return &Throttler{
		delay: time.Duration(delayMs) * time.Millisecond,
	}
}

func (t *Throttler) Wait() {
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
