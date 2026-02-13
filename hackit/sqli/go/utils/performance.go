package utils

import (
	"sync"
	"time"
)

// PerformanceManager handles caching and retry logic
type PerformanceManager struct {
	Cache      map[string][]byte
	CacheLock  sync.RWMutex
	RetryCount int
	Delay      time.Duration
}

func NewPerformanceManager(retries int, delay time.Duration) *PerformanceManager {
	return &PerformanceManager{
		Cache:      make(map[string][]byte),
		RetryCount: retries,
		Delay:      delay,
	}
}

func (pm *PerformanceManager) GetFromCache(key string) ([]byte, bool) {
	pm.CacheLock.RLock()
	defer pm.CacheLock.RUnlock()
	val, ok := pm.Cache[key]
	return val, ok
}

func (pm *PerformanceManager) SetToCache(key string, data []byte) {
	pm.CacheLock.Lock()
	defer pm.CacheLock.Unlock()
	pm.Cache[key] = data
}

func (pm *PerformanceManager) ShouldRetry(attempt int) bool {
	return attempt < pm.RetryCount
}
