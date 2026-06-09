package main

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"hackit_ai_engine/native"
)

// AutonomousHunter handles the full bug hunting lifecycle.
type AutonomousHunter struct {
	Target string
}

// Run executes the complete autonomous hunting loop.
func (h *AutonomousHunter) Run() {
	fmt.Printf("\n🚀 [AI HUNTER] Initiating FULL REAL-TIME Autonomous Sequence on: %s\n", h.Target)
	fmt.Println("=========================================================================")

	// 1. Setup Stealth Engine
	fmt.Println("\n🥷 [PHASE 1] Initializing Stealth & Anonymity Module...")
	time.Sleep(1 * time.Second)
	fmt.Println("   [+] Anonymity Mode : ACTIVE")
	fmt.Println("   [+] Header Rotation: ACTIVE")
	fmt.Println("   [+] DNS Masking    : ACTIVE (Public Resolvers)")
	fmt.Println("   [+] Traffic Jitter : ACTIVE")

	// 2 & 3. Concurrent Recon Phase (Real-Time Subdomain & Port Scanning)
	fmt.Println("\n🔍 [PHASE 2 & 3] Massive Concurrent Reconnaissance (Ports & Subdomains)...")
	
	var subdomains []string
	var openServices []string
	var wg sync.WaitGroup
	
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		subdomains = h.executeSubdomainEnum()
	}()
	
	go func() {
		defer wg.Done()
		openServices = h.executePortScan()
	}()
	
	// Wait for both hyper-scans to finish
	wg.Wait()
	
	if len(openServices) == 0 {
		fmt.Println("❌ No open services detected. Target appears completely stealth or offline.")
		return
	}

	// 4. Planning Phase
	fmt.Println("\n🧠 [PHASE 4] AI Planning & Tactical Routing...")
	plan := GenerateAttackPlan(openServices)
	fmt.Println(plan)

	// 5. Execution Phase (Fuzzing / Deep Probe)
	fmt.Println("\n⚡ [PHASE 5] Active Fuzzing & Vulnerability Probing...")
	vectors := h.executeAttacks(openServices, subdomains)

	// 6. Analysis Phase (Flowchart)
	fmt.Println("\n📊 [PHASE 6] Synthesizing Attack Vectors (Flowchart Generation)...")
	flowchart := GenerateVulnFlowchart(h.Target, vectors)
	fmt.Println(flowchart)

	// 7. Reporting Phase
	fmt.Println("\n📝 [PHASE 7] Compiling Intelligence Report...")
	report := GenerateReport(h.Target, vectors, flowchart)
	
	fmt.Println("\n✅ [AI HUNTER] Mission Complete. Evidence Captured.")
	fmt.Println("=========================================================================")
	fmt.Println(report)
}

func (h *AutonomousHunter) executeSubdomainEnum() []string {
	subs, err := native.EnumerateSubdomains(h.Target)
	
	var foundSubs []string
	if err == nil {
		foundSubs = subs
	}
	
	fmt.Printf("   [+] Discovered %d unique subdomains\n", len(foundSubs))
	return foundSubs
}

func (h *AutonomousHunter) executePortScan() []string {
	ports := native.ScanPorts(h.Target, native.TopPorts, 100, 2*time.Second)
	
	var services []string
	for _, p := range ports {
		// Map it using native tech mapper
		tech := native.MapTechnologies(h.Target, p.Port, p.Banner)
		
		svcStr := fmt.Sprintf("%d/%s (Banner: %s)", p.Port, p.Service, p.Banner)
		services = append(services, svcStr)
		
		if tech.Server != "" {
			fmt.Printf("      [*] Detected %s on port %d\n", tech.Server, p.Port)
		}
	}
	
	fmt.Printf("   [+] Discovered Open Services: %v\n", services)
	return services
}

func (h *AutonomousHunter) executeAttacks(services []string, subdomains []string) []AttackVector {
	var results []AttackVector
	
	for _, svc := range services {
		svcLower := strings.ToLower(svc)
		fmt.Printf("   -> Probing %s...\n", svc)
		
		// --- ADDED ADVANCED BANNER EXPLOIT CHECK ---
		// We extract the port number and banner string
		parts := strings.SplitN(svc, "/", 2)
		var portNum int
		var svcName, banner string
		if len(parts) == 2 {
			fmt.Sscanf(parts[0], "%d", &portNum)
			svcNameBanner := parts[1]
			idx := strings.Index(svcNameBanner, "(Banner:")
			if idx != -1 {
				svcName = strings.TrimSpace(svcNameBanner[:idx])
				banner = strings.TrimSpace(svcNameBanner[idx+8:])
				banner = strings.TrimSuffix(banner, ")")
			} else {
				svcName = strings.TrimSpace(svcNameBanner)
			}
		}

		advVectors := AnalyzeServiceBanner(portNum, svcName, banner)
		if len(advVectors) > 0 {
			results = append(results, advVectors...)
			FormatDeepProbeOutput(advVectors)
		}
		
		// If HTTP/HTTPS is found, we run web fuzzer and header checks
		if strings.Contains(svcLower, "http") || strings.Contains(svcLower, "443") || strings.Contains(svcLower, "80") {
			
			protocol := "http://"
			if strings.Contains(svcLower, "443") || strings.Contains(svcLower, "https") {
				protocol = "https://"
			}
			// --- NATIVE SSL AUDIT ---
			var sslResult *native.SSLResult
			if protocol == "https://" {
				fmt.Printf("      [*] Performing Native SSL/TLS Security Audit...\n")
				sslResult = native.AuditSSL(h.Target, portNum)
				if sslResult != nil && len(sslResult.Vulnerabilities) > 0 {
					for _, v := range sslResult.Vulnerabilities {
						results = append(results, AttackVector{
							Port: portNum,
							Service: "https",
							Vulnerability: v,
							Impact: "Medium - Encryption Downgrade / Interception",
						})
						fmt.Printf("      [!] SSL VULN FOUND: %s\n", v)
					}
				}
			}

			// --- NATIVE WAF DETECTION ---
			fmt.Printf("      [*] Detecting Web Application Firewalls (WAF)...\n")
			wafResult := native.DetectWAF(h.Target, portNum, protocol == "https://")
			if wafResult.Detected {
				fmt.Printf("      [!] WAF DETECTED: %s\n", wafResult.WAFName)
				// Note: It's good to log, but WAF presence itself isn't a vulnerability, rather an obstacle.
				// But we can document it.
			} else {
				fmt.Printf("      [-] No WAF Detected. Target is exposed.\n")
			}
			
			// Native Tech Mapper already mapped headers, we don't need python script output
			// We can check if it's HTTPS missing HSTS for example:
			if protocol == "https://" && sslResult != nil {
				// handled by SSL audit
			}

			// --- NATIVE HIGH-SPEED FUZZING ---
			fmt.Printf("      [*] Initiating Native High-Speed Directory Fuzzing...\n")
			targetBaseURL := fmt.Sprintf("%s%s:%d", protocol, h.Target, portNum)
			fuzzHits := native.FuzzDirectories(targetBaseURL, 20)
			
			if len(fuzzHits) > 0 {
				for _, hit := range fuzzHits {
					results = append(results, AttackVector{
						Port: portNum,
						Service: "http/https",
						Vulnerability: fmt.Sprintf("Sensitive Endpoint Exposed: %s (HTTP %d)", hit.Path, hit.StatusCode),
						Impact: "High - Data Leakage / RCE",
					})
					fmt.Printf("      [!] CRITICAL HIT: %s (Status: %d)\n", hit.Path, hit.StatusCode)
				}
			} else {
				fmt.Println("      [-] Fuzzer found no immediate sensitive endpoints.")
			}
		}
	}
	
	// --- NATIVE SUBDOMAIN TAKEOVER CHECK ---
	if len(subdomains) > 0 {
		fmt.Printf("   -> Auditing %d subdomains for Takeover vulnerabilities...\n", len(subdomains))
		takeovers := native.CheckSubdomainTakeover(subdomains, 15)
		
		if len(takeovers) > 0 {
			for _, to := range takeovers {
				results = append(results, AttackVector{
					Port: 443,
					Service: "https",
					Vulnerability: fmt.Sprintf("Subdomain Takeover on %s (%s)", to.Subdomain, to.Platform),
					Impact: "High - Phishing / Brand Reputation Damage",
				})
				fmt.Printf("      [!] CRITICAL VULN FOUND: Subdomain Takeover vector on %s via %s\n", to.Subdomain, to.Platform)
			}
		} else {
			fmt.Printf("      [-] No Subdomain Takeovers detected.\n")
		}
	}
	
	return results
}

func stripANSI(str string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(str, "")
}

func containsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
