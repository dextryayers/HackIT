package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
)

type Result struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
}

type Output struct {
	Target     string   `json:"target"`
	AliveCount int      `json:"alive_count"`
	Hosts      []Result `json:"hosts"`
}

func main() {
	cidr := flag.String("cidr", "", "Target CIDR")
	timeout := flag.Int("timeout", 1000, "Timeout ms")
	concurrency := flag.Int("threads", 100, "Threads")
	flag.Parse()

	if *cidr == "" {
		fmt.Println(`{"error": "CIDR required"}`)
		os.Exit(1)
	}

	hosts, err := ParseCIDR(*cidr)
	if err != nil {
		// Try as single IP
		if net.ParseIP(*cidr) != nil {
			hosts = []string{*cidr}
		} else {
			fmt.Printf(`{"error": "Invalid CIDR: %v"}`, err)
			os.Exit(1)
		}
	}

	results := runScan(hosts, *timeout, *concurrency)

	out := Output{
		Target:     *cidr,
		AliveCount: len(results),
		Hosts:      results,
	}

	jsonOut, _ := json.Marshal(out)
	fmt.Println(string(jsonOut))
}

func runScan(hosts []string, timeoutMs int, threads int) []Result {
	var results []Result
	var mutex sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			if IsAlive(ip, timeoutMs) {
				hostname := LookupHost(ip)

				mutex.Lock()
				results = append(results, Result{IP: ip, Hostname: hostname})
				mutex.Unlock()
			}
		}(h)
	}

	wg.Wait()
	return results
}
