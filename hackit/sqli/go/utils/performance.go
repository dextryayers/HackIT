package utils

import (
	"crypto/md5"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// PerformanceManager handles caching, retry, connection pooling, and rate limiting
type PerformanceManager struct {
	Cache       *ResponseCache
	RetryCount  int
	Delay       time.Duration
	RateLimiter *RateLimiter
	Pool        *ConnPool
	Stats       *PerfStats
}

// PerfStats tracks performance metrics
type PerfStats struct {
	TotalRequests   int64
	CacheHits       int64
	CacheMisses     int64
	Retries         int64
	FailedRequests  int64
	AvgResponseTime int64 // nanoseconds
	MinResponseTime int64
	MaxResponseTime int64
	mu              sync.Mutex
}

// ResponseCache with TTL and LRU eviction
type ResponseCache struct {
	entries map[string]*CacheEntry
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
	lru     []string
}

type CacheEntry struct {
	Data      []byte
	ExpiresAt time.Time
	HitCount  int64
}

// RateLimiter adaptive rate limiting
type RateLimiter struct {
	mu              sync.Mutex
	responseTimes   []time.Duration
	minDelay        time.Duration
	maxDelay        time.Duration
	currentDelay    time.Duration
	consecutiveFast int
	consecutiveSlow int
	slowThreshold   time.Duration
	fastThreshold   time.Duration
	targetRate      float64 // requests per second
}

// ConnPool manages reusable connections
type ConnPool struct {
	active int32
	max    int32
	min    int32
	mu     sync.Mutex
}

// PriorityQueue for request prioritization
type PriorityQueue []*PriorityItem

type PriorityItem struct {
	Key      string
	Priority int
	Index    int
}

func (pq PriorityQueue) Len() int { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool { return pq[i].Priority < pq[j].Priority }
func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}
func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*PriorityItem)
	item.Index = n
	*pq = append(*pq, item)
}
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.Index = -1
	*pq = old[0 : n-1]
	return item
}

func NewPerformanceManager(retries int, delay time.Duration) *PerformanceManager {
	return &PerformanceManager{
		Cache:      NewResponseCache(10000, 5*time.Minute),
		RetryCount: retries,
		Delay:      delay,
		RateLimiter: NewRateLimiter(),
		Pool:       NewConnPool(50, 5),
		Stats:      &PerfStats{},
	}
}

func NewResponseCache(maxSize int, ttl time.Duration) *ResponseCache {
	return &ResponseCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		minDelay:        0,
		maxDelay:        5 * time.Second,
		currentDelay:    0,
		slowThreshold:   3 * time.Second,
		fastThreshold:   500 * time.Millisecond,
		targetRate:      10.0, // 10 requests/second target
	}
}

func NewConnPool(max, min int32) *ConnPool {
	return &ConnPool{max: max, min: min}
}

func (pm *PerformanceManager) GetFromCache(key string) ([]byte, bool) {
	atomic.AddInt64(&pm.Stats.TotalRequests, 1)

	hash := hashKey(key)
	pm.Cache.mu.RLock()
	entry, ok := pm.Cache.entries[hash]
	pm.Cache.mu.RUnlock()

	if !ok {
		atomic.AddInt64(&pm.Stats.CacheMisses, 1)
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		pm.Cache.mu.Lock()
		delete(pm.Cache.entries, hash)
		pm.Cache.mu.Unlock()
		atomic.AddInt64(&pm.Stats.CacheMisses, 1)
		return nil, false
	}

	atomic.AddInt64(&entry.HitCount, 1)
	atomic.AddInt64(&pm.Stats.CacheHits, 1)
	return entry.Data, true
}

func (pm *PerformanceManager) SetToCache(key string, data []byte) {
	hash := hashKey(key)

	pm.Cache.mu.Lock()
	defer pm.Cache.mu.Unlock()

	// LRU eviction
	if len(pm.Cache.entries) >= pm.Cache.maxSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range pm.Cache.entries {
			if oldestKey == "" || v.ExpiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.ExpiresAt
			}
		}
		delete(pm.Cache.entries, oldestKey)
	}

	pm.Cache.entries[hash] = &CacheEntry{
		Data:      data,
		ExpiresAt: time.Now().Add(pm.Cache.ttl),
		HitCount:  0,
	}
}

func (pm *PerformanceManager) ShouldRetry(attempt int) bool {
	return attempt < pm.RetryCount
}

func (pm *PerformanceManager) RecordResponse(duration time.Duration, success bool) {
	stats := pm.Stats
	stats.mu.Lock()

	ns := duration.Nanoseconds()
	if stats.MinResponseTime == 0 || ns < stats.MinResponseTime {
		stats.MinResponseTime = ns
	}
	if ns > stats.MaxResponseTime {
		stats.MaxResponseTime = ns
	}
	// Exponential moving average
	if stats.AvgResponseTime == 0 {
		stats.AvgResponseTime = ns
	} else {
		stats.AvgResponseTime = (stats.AvgResponseTime*3 + ns) / 4
	}

	if !success {
		atomic.AddInt64(&stats.FailedRequests, 1)
	}

	stats.mu.Unlock()
	pm.RateLimiter.RecordResponseTime(duration)
}

func (pm *PerformanceManager) GetAdaptiveDelay() time.Duration {
	return pm.RateLimiter.GetDelay()
}

func (pm *PerformanceManager) GetCacheSize() int {
	pm.Cache.mu.RLock()
	defer pm.Cache.mu.RUnlock()
	return len(pm.Cache.entries)
}

func (pm *PerformanceManager) ClearCache() {
	pm.Cache.mu.Lock()
	pm.Cache.entries = make(map[string]*CacheEntry)
	pm.Cache.mu.Unlock()
}

func (rl *RateLimiter) RecordResponseTime(d time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.responseTimes = append(rl.responseTimes, d)
	if len(rl.responseTimes) > 50 {
		rl.responseTimes = rl.responseTimes[len(rl.responseTimes)-50:]
	}

	if d > rl.slowThreshold {
		rl.consecutiveSlow++
		rl.consecutiveFast = 0
		if rl.consecutiveSlow >= 3 {
			rl.currentDelay += 500 * time.Millisecond
			if rl.currentDelay > rl.maxDelay {
				rl.currentDelay = rl.maxDelay
			}
		}
	} else if d < rl.fastThreshold {
		rl.consecutiveFast++
		rl.consecutiveSlow = 0
		if rl.consecutiveFast >= 10 {
			rl.currentDelay -= 200 * time.Millisecond
			if rl.currentDelay < rl.minDelay {
				rl.currentDelay = rl.minDelay
			}
		}
	} else {
		rl.consecutiveFast = 0
		rl.consecutiveSlow = 0
	}
}

func (rl *RateLimiter) GetDelay() time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.currentDelay
}

func (cp *ConnPool) Acquire() bool {
	cur := atomic.LoadInt32(&cp.active)
	if cur >= cp.max {
		return false
	}
	atomic.AddInt32(&cp.active, 1)
	return true
}

func (cp *ConnPool) Release() {
	atomic.AddInt32(&cp.active, -1)
}

func (cp *ConnPool) Active() int32 {
	return atomic.LoadInt32(&cp.active)
}

func (pm *PerformanceManager) GetStats() *PerfStats {
	return pm.Stats
}

func hashKey(key string) string {
	h := md5.Sum([]byte(key))
	return hex.EncodeToString(h[:])
}
