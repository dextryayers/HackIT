package main

import (
	"sync"
	"time"
)

func runPassive(domain string) []string {
	var subs []string

	// Channels to collect results from multiple sources in parallel
	ch := make(chan []string)
	sources := []ProviderFunc{
		queryCrtSh,
		queryChaos,
		queryC99,
		queryHackerTarget,
		queryAlienVault,
		queryThreatCrowd,
		queryAnubis,
		queryRapiddns,
		querySublist3r,
		queryWayback,
		queryUrlScan,
		queryBufferOver,
		queryThreatMiner,
		queryCertSpotter,
		querySonar,
		queryCommonCrawl,
		queryDigitorus,
		queryNetlas,
		querySubdomainCenter,
		querySitedossier,
		queryRiddler,
		queryRobtex,
		queryBaidu,
		queryYahoo,
		queryBing,
		queryGoogle,
		queryDuckDuckGo,
		queryShodan,
		querySecurityTrails,
		queryAhrefs,
	}

	// Use WaitGroup to close channel when done
	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)
		go func(f ProviderFunc) {
			defer wg.Done()

			// Source-level timeout to prevent one slow source from hanging the whole scan
			resultChan := make(chan []string, 1)
			go func() {
				resultChan <- f(domain)
			}()

			select {
			case res := <-resultChan:
				ch <- res
			case <-time.After(90 * time.Second): // Max 90 seconds per source
				// Source timed out, skip it
				return
			}
		}(source)
	}

	// Closer routine
	go func() {
		wg.Wait()
		close(ch)
	}()

	// Collect
	for res := range ch {
		subs = append(subs, res...)
	}

	return unique(subs)
}
