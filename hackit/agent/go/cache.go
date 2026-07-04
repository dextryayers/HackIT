package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CacheEntry struct {
	Response  string    `json:"response"`
	CreatedAt time.Time `json:"created_at"`
	TTL       int       `json:"ttl_seconds"`
}

type ResponseCache struct {
	mu       sync.RWMutex
	dir      string
	entries  map[string]CacheEntry
	enabled  bool
}

func NewResponseCache() *ResponseCache {
	home, _ := os.UserHomeDir()
	cacheDir := filepath.Join(home, ".hackit", "cache")
	os.MkdirAll(cacheDir, 0755)

	return &ResponseCache{
		dir:     cacheDir,
		entries: make(map[string]CacheEntry),
		enabled: true,
	}
}

func (c *ResponseCache) key(provider, model, prompt, system string) string {
	data := fmt.Sprintf("%s|%s|%s|%s", provider, model, prompt, system)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16])
}

func (c *ResponseCache) Get(provider, model, prompt, system string) (string, bool) {
	if !c.enabled {
		return "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	k := c.key(provider, model, prompt, system)
	entry, ok := c.entries[k]
	if !ok {
		// Try disk
		diskPath := filepath.Join(c.dir, k+".json")
		data, err := os.ReadFile(diskPath)
		if err == nil {
			var diskEntry CacheEntry
			if json.Unmarshal(data, &diskEntry) == nil {
				if time.Since(diskEntry.CreatedAt).Seconds() < float64(diskEntry.TTL) {
					c.entries[k] = diskEntry
					return diskEntry.Response, true
				}
				os.Remove(diskPath)
			}
		}
		return "", false
	}

	if time.Since(entry.CreatedAt).Seconds() < float64(entry.TTL) {
		return entry.Response, true
	}

	// Expired
	delete(c.entries, k)
	diskPath := filepath.Join(c.dir, k+".json")
	os.Remove(diskPath)
	return "", false
}

func (c *ResponseCache) Set(provider, model, prompt, system, response string, ttl int) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	k := c.key(provider, model, prompt, system)
	entry := CacheEntry{
		Response:  response,
		CreatedAt: time.Now(),
		TTL:       ttl,
	}
	c.entries[k] = entry

	// Write to disk async
	go func() {
		diskPath := filepath.Join(c.dir, k+".json")
		data, _ := json.Marshal(entry)
		os.WriteFile(diskPath, data, 0644)
	}()
}

func (c *ResponseCache) Invalidate(provider string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k := range c.entries {
		c.entries[k] = CacheEntry{
			Response:  c.entries[k].Response,
			CreatedAt: time.Time{},
			TTL:       -1,
		}
	}
}
