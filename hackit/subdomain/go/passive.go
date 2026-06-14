package main

import (
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

func runPassive(domain string, ch chan<- []string, verbose bool) {
	sources := []ProviderFunc{
		queryCrtSh,
		queryChaos,
		queryC99,
		queryHackerTarget,
		queryOTX,
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
		queryFullHunt,
		queryYandex,
		queryVirusTotal,
		queryColumbus,
		queryDNSDumpster,
		queryBuiltWith,
		queryCensys,
		queryFofa,
		queryZoomeye,
		queryLeakix,
		queryIntelx,
		queryNetcraft,
		queryPublicWWW,
		queryCriminalIP,
		queryQuake,
		queryDnsHistory,
		queryViewDNS,
		queryDNSRepo,
		queryDnsWatch,
		queryReverseIP,
		queryWhoisXMLAPI,
		queryDomainBigData,
		queryDnslytics,
		querySiteAdvisor,
		queryGoogleCT,
		queryFacebookCT,
		querySSLMate,
		queryHybridAnalysis,
		queryAsk,
		queryGitHub,
		queryGitLab,
		queryBitbucket,
		querySourceForge,
		queryCertDB,
		queryBinaryEdge,
		queryDNSDB,
		queryPassiveTotal,
		queryGitea,
		queryBeVigil,
		queryGrepApp,
	}

	// 1. Linux Rust OSINT Engine
	if runtime.GOOS == "linux" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rustSubs := linuxRustOSINTScan(domain)
			if len(rustSubs) > 0 {
				if verbose {
					fmt.Printf("[*] Rust OSINT Engine found %d subdomains\n", len(rustSubs))
				}
				ch <- rustSubs
			}
		}()
	}

	// 2. Windows Rust OSINT Engine
	if runtime.GOOS == "windows" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rustOSINTScan != nil && rustOSINTScan.Find() == nil {
				cDomain := []byte(domain + "\x00")
				ptr, _, _ := rustOSINTScan.Call(uintptr(unsafe.Pointer(&cDomain[0])))
				if ptr != 0 {
					rustRes := string(CStrToGo(ptr))
					if rustRes != "" {
						subs := strings.Split(rustRes, ",")
						if verbose {
							fmt.Printf("[*] Rust OSINT Engine found %d subdomains\n", len(subs))
						}
						ch <- subs
					}
				}
			}
		}()
	}

	// 3. Go-based passive sources with concurrency limit
	concurrency := 30
	sem := make(chan struct{}, concurrency)

	for _, source := range sources {
		wg.Add(1)
		sem <- struct{}{}
		go func(f ProviderFunc) {
			defer wg.Done()
			defer func() { <-sem }()

			resultChan := make(chan []string, 1)
			go func() {
				resultChan <- f(domain)
			}()

			select {
			case res := <-resultChan:
				if len(res) > 0 {
					if verbose {
						fmt.Printf("[*] Found %d subdomains from passive source\n", len(res))
					}
					ch <- res
				}
			case <-time.After(20 * time.Second):
			}
		}(source)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()
}
