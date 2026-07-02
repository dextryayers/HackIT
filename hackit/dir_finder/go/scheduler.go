package main

import (
	"math"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Scheduler struct {
	mu              sync.Mutex
	concurrency     int32
	baseConcurrency int
	minConcurrency  int
	maxConcurrency  int

	totalRequests int64
	totalErrors   int64
	errorRate     float64
	windowStart   time.Time
	windowReq     int64
	windowErr     int64

	jitterEnabled bool
	jitterMin     time.Duration
	jitterMax     time.Duration

	lastAdjust time.Time
	adjustCooldown time.Duration
}

func NewScheduler(baseConcurrency int) *Scheduler {
	minC := 1
	if baseConcurrency > 20 {
		minC = baseConcurrency / 4
	} else if baseConcurrency > 5 {
		minC = 2
	}
	return &Scheduler{
		concurrency:     int32(baseConcurrency),
		baseConcurrency: baseConcurrency,
		minConcurrency:  minC,
		maxConcurrency:  baseConcurrency * 2,
		windowStart:     time.Now(),
		adjustCooldown:  5 * time.Second,
	}
}

func (s *Scheduler) RecordRequest(err bool) {
	atomic.AddInt64(&s.totalRequests, 1)
	atomic.AddInt64(&s.windowReq, 1)
	if err {
		atomic.AddInt64(&s.totalErrors, 1)
		atomic.AddInt64(&s.windowErr, 1)
	}
}

func (s *Scheduler) Concurrency() int {
	return int(atomic.LoadInt32(&s.concurrency))
}

func (s *Scheduler) ErrorRate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.errorRate
}

func (s *Scheduler) AdjustIfNeeded() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Since(s.lastAdjust) < s.adjustCooldown {
		return
	}
	s.lastAdjust = time.Now()

	elapsed := time.Since(s.windowStart).Seconds()
	if elapsed < 3 {
		return
	}

	req := atomic.SwapInt64(&s.windowReq, 0)
	err := atomic.SwapInt64(&s.windowErr, 0)
	s.windowStart = time.Now()

	if req == 0 {
		return
	}

	rate := float64(err) / float64(req)
	s.errorRate = rate

	cur := int(atomic.LoadInt32(&s.concurrency))

	switch {
	case rate > 0.3 && cur > s.minConcurrency:
		newC := int(math.Max(float64(s.minConcurrency), float64(cur)/2))
		atomic.StoreInt32(&s.concurrency, int32(newC))
	case rate < 0.05 && cur < s.maxConcurrency:
		newC := int(math.Min(float64(s.maxConcurrency), float64(cur)+2))
		atomic.StoreInt32(&s.concurrency, int32(newC))
	}
}

func (s *Scheduler) JitterDelay() time.Duration {
	if !s.jitterEnabled {
		return 0
	}
	s.mu.Lock()
	minD := s.jitterMin
	maxD := s.jitterMax
	s.mu.Unlock()
	if maxD <= minD {
		return 0
	}
	return minD + time.Duration(rand.Int63n(int64(maxD-minD)))
}

func (s *Scheduler) EnableJitter(minMs, maxMs int) {
	s.mu.Lock()
	s.jitterEnabled = true
	s.jitterMin = time.Duration(minMs) * time.Millisecond
	s.jitterMax = time.Duration(maxMs) * time.Millisecond
	s.mu.Unlock()
}

func (s *Scheduler) Stats() (totalReq, totalErr int64, errRate float64) {
	return atomic.LoadInt64(&s.totalRequests),
		atomic.LoadInt64(&s.totalErrors),
		s.ErrorRate()
}

type PathPriority struct {
	Path     string
	Priority int
	Depth    int
	Length   int
}

type PrioritizedQueue struct {
	items []PathPriority
	mu    sync.Mutex
}

func NewPrioritizedQueue(paths []string) *PrioritizedQueue {
	q := &PrioritizedQueue{}
	for _, p := range paths {
		depth := PathDepth(p)
		length := len(p)
		priority := 0
		if depth <= 1 {
			priority = 10
		} else if depth <= 3 {
			priority = 7
		} else {
			priority = 3
		}
		if length < 20 {
			priority += 2
		}
		if stringsHasAnyPrefix(p, []string{"/admin", "/login", "/api", "/wp-", ".env", "/config", "/backup", "/.git", "/.env"}) {
			priority += 5
		}
		q.items = append(q.items, PathPriority{Path: p, Priority: priority, Depth: depth, Length: length})
	}
	sort.Slice(q.items, func(i, j int) bool {
		if q.items[i].Priority != q.items[j].Priority {
			return q.items[i].Priority > q.items[j].Priority
		}
		return q.items[i].Length < q.items[j].Length
	})
	return q
}

func stringsHasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if stringsHasPrefix(s, p) {
			return true
		}
	}
	return false
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func (q *PrioritizedQueue) Next() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return ""
	}
	item := q.items[0]
	q.items = q.items[1:]
	return item.Path
}

func (q *PrioritizedQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

func (q *PrioritizedQueue) Add(path string, basePriority int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	depth := PathDepth(path)
	length := len(path)
	priority := basePriority
	if depth <= 1 {
		priority += 10
	} else if depth <= 3 {
		priority += 7
	} else {
		priority += 3
	}
	if length < 20 {
		priority += 2
	}
	q.items = append(q.items, PathPriority{Path: path, Priority: priority, Depth: depth, Length: length})
	sort.Slice(q.items, func(i, j int) bool {
		return q.items[i].Priority > q.items[j].Priority
	})
}

func exponentialBackoff(retry int, base time.Duration) time.Duration {
	return time.Duration(float64(base) * math.Pow(2, float64(retry)))
}

func jitter(d time.Duration, maxJitter time.Duration) time.Duration {
	if maxJitter <= 0 {
		return d
	}
	j := time.Duration(rand.Int63n(int64(maxJitter)))
	return d + j
}
