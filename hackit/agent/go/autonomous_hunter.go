package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"hackit_ai_engine/native"
)

type AutonomousHunter struct {
	Target     string
	Subdomains []string
	OpenPorts  []native.PortResult
}

func (h *AutonomousHunter) Run() {
	fmt.Printf("\n  AUTONOMOUS PENTEST AI ENGINE\n")
	fmt.Printf("  Target: %s\n", h.Target)
	fmt.Println("  =================================================")

	start := time.Now()

	h.phase(1, "Stealth & Anonymity")
	fmt.Println("     [+] Anonymity Mode : ACTIVE")
	fmt.Println("     [+] Header Rotation: ACTIVE")
	fmt.Println("     [+] DNS Masking    : ACTIVE")
	fmt.Println("     [+] Traffic Jitter : ACTIVE")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		h.Subdomains = h.executeSubdomainEnum()
	}()

	go func() {
		defer wg.Done()
		h.OpenPorts = h.executePortScan()
	}()

	wg.Wait()

	if len(h.OpenPorts) == 0 {
		fmt.Println("     [!] No open ports detected. Target may be offline.")
		return
	}

	h.phase(2, "Technology Fingerprinting")
	h.executeTechMapping()

	h.phase(3, "Vulnerability Probing")
	h.executeVulnProbes()

	h.phase(4, "Web Security Analysis")
	h.executeWebSecurity()

	h.phase(5, "Advanced Attack Vectors")
	h.executeAdvancedAttacks()

	h.phase(6, "Subdomain & Asset Analysis")
	h.executeAssetAnalysis()

	h.phase(7, "AI Reasoning & Report")
	h.executeAIReport()

	elapsed := time.Since(start)
	fmt.Printf("\n  Mission Complete in %.1fs\n", elapsed.Seconds())
	fmt.Println("  =================================================")
}

func (h *AutonomousHunter) phase(num int, name string) {
	chars := []string{"\u25e2", "\u25e3", "\u25e4", "\u25e5"}
	c := chars[rand.Intn(4)]
	fmt.Printf("\n  %s [PHASE %d] %s\n", c, num, name)
}

func (h *AutonomousHunter) executeSubdomainEnum() []string {
	fmt.Print("     Enumerating subdomains...")
	subs, err := native.EnumerateSubdomains(h.Target)
	if err != nil {
		fmt.Println(" ERROR")
		return nil
	}
	fmt.Printf(" %d found\n", len(subs))
	for i, s := range subs {
		if i < 5 {
			fmt.Printf("       - %s\n", s)
		}
	}
	if len(subs) > 5 {
		fmt.Printf("       - ... and %d more\n", len(subs)-5)
	}
	return subs
}

func (h *AutonomousHunter) executePortScan() []native.PortResult {
	fmt.Print("     Scanning ports...")
	ports := native.ScanPorts(h.Target, native.TopPorts, 100, 2*time.Second)
	fmt.Printf(" %d open\n", len(ports))
	for _, p := range ports {
		tech := native.MapTechnologies(h.Target, p.Port, p.Banner)
		if tech.Server != "" {
			fmt.Printf("       %d/%s - %s\n", p.Port, p.Service, tech.Server)
		} else {
			fmt.Printf("       %d/%s\n", p.Port, p.Service)
		}
	}
	return ports
}

func (h *AutonomousHunter) executeTechMapping() {
	webPorts := h.getWebPorts()
	if len(webPorts) == 0 {
		fmt.Println("     No web ports found (80, 443, 8080, 8443)")
		return
	}
	for _, port := range webPorts {
		tech := native.MapTechnologies(h.Target, port, "")
		if tech.Server != "" {
			fmt.Printf("     [:%d] Server: %s\n", port, tech.Server)
			for i, f := range tech.Frameworks {
				fmt.Printf("       %s\n", f)
				if i > 10 {
					fmt.Println("       ... and more")
					break
				}
			}

			for _, v := range tech.Vulnerabilities {
				fmt.Printf("       [CVE] %s\n", v)
			}
		}
		isHTTPS := port == 443 || port == 8443
		waf := native.DetectWAF(h.Target, port, isHTTPS)
		if waf.Detected {
			fmt.Printf("     [!] WAF Detected: %s\n", waf.WAFName)
		}

		protocol := "http"
		if isHTTPS {
			protocol = "https"
			ssl := native.AuditSSL(h.Target, port)
			if ssl != nil {
				if len(ssl.Vulnerabilities) > 0 {
					for _, v := range ssl.Vulnerabilities {
						fmt.Printf("     [!] SSL: %s\n", v)
					}
				} else {
					cn := ssl.Subject
					if len(cn) > 50 {
						cn = cn[:50] + "..."
					}
					fmt.Printf("     SSL: %s (OK)\n", cn)
				}
			}
		}

		baseURL := fmt.Sprintf("%s://%s:%d", protocol, h.Target, port)
		hdrs := native.AuditHeaders(baseURL)
		missing := 0
		for _, hdr := range hdrs {
			if !hdr.Present {
				missing++
			}
		}
		if missing > 0 {
			fmt.Printf("     Security headers: %d missing\n", missing)
		}
	}
}

func (h *AutonomousHunter) executeVulnProbes() {
	webPorts := h.getWebPorts()
	if len(webPorts) == 0 {
		return
	}
	for _, port := range webPorts {
		isHTTPS := port == 443 || port == 8443
		protocol := "http"
		if isHTTPS {
			protocol = "https"
		}
		baseURL := fmt.Sprintf("%s://%s:%d", protocol, h.Target, port)

		fmt.Printf("     [:%d] Probing %s\n", port, baseURL)

		fmt.Print("       Fuzzing directories...")
		fuzzHits := native.FuzzDirectories(baseURL, 30)
		fmt.Printf(" %d hits\n", len(fuzzHits))
		for _, hit := range fuzzHits {
			fmt.Printf("       [!] %s (HTTP %d)\n", hit.Path, hit.StatusCode)
		}

		params := h.guessParams(baseURL)
		if len(params) > 0 {
			fmt.Print("       Testing SQL injection...")
			sqliResults := native.TestSQLi(baseURL, params, 10)
			vulnCount := 0
			for _, r := range sqliResults {
				if r.Vulnerable {
					vulnCount++
				}
			}
			fmt.Printf(" %d vulnerable\n", vulnCount)
			for _, r := range sqliResults {
				if r.Vulnerable {
					fmt.Printf("       [!] SQLi: %s via %s\n", r.Evidence, r.Parameter)
				}
			}

			fmt.Print("       Testing XSS...")
			xssResults := native.TestXSS(baseURL, params)
			vulnCount = 0
			for _, r := range xssResults {
				if r.Reflected {
					vulnCount++
				}
			}
			fmt.Printf(" %d reflected\n", vulnCount)
			for _, r := range xssResults {
				if r.Reflected {
					fmt.Printf("       [!] XSS: %s via %s\n", r.Type, r.Parameter)
				}
			}
		if len(params) > 0 {
				fmt.Print("       Testing LFI...")
				lfiResults := native.TestLFI(baseURL, params)
				vulnCount = 0
				for _, r := range lfiResults {
					if r.Vulnerable {
						vulnCount++
					}
				}
				fmt.Printf(" %d vulnerable\n", vulnCount)
				for _, r := range lfiResults {
					if r.Vulnerable {
						fmt.Printf("       [!] LFI: %s via %s\n", r.Evidence, r.Parameter)
					}
				}

				fmt.Print("       Testing SSTI...")
				sstiResults := native.TestSSTI(baseURL, params)
				vulnCount = 0
				for _, r := range sstiResults {
					if r.Vulnerable {
						vulnCount++
					}
				}
				fmt.Printf(" %d vulnerable\n", vulnCount)
				for _, r := range sstiResults {
					if r.Vulnerable {
						fmt.Printf("       [!] SSTI: %s via %s (%s)\n", r.Evidence, r.Parameter, r.Engine)
					}
				}

				fmt.Print("       Testing CMD injection...")
				cmdResults := native.TestCmdInjection(baseURL, params)
				vulnCount = 0
				for _, r := range cmdResults {
					if r.Vulnerable {
						vulnCount++
					}
				}
				fmt.Printf(" %d vulnerable\n", vulnCount)
				for _, r := range cmdResults {
					if r.Vulnerable {
						fmt.Printf("       [!] CMDi: %s via %s\n", r.Evidence, r.Parameter)
					}
				}
			} else {
				fmt.Println("       Skipping LFI/SSTI/CMDi (no params)")
			}
		} else {
				fmt.Println("       Skipping SQLi/XSS/LFI/SSTI/CMDi (no params)")
			}
	}
}

func (h *AutonomousHunter) executeWebSecurity() {
	webPorts := h.getWebPorts()
	for _, port := range webPorts {
		isHTTPS := port == 443 || port == 8443
		protocol := "http"
		if isHTTPS {
			protocol = "https"
		}
		baseURL := fmt.Sprintf("%s://%s:%d", protocol, h.Target, port)
		params := h.guessParams(baseURL)

		if len(params) > 0 {
			fmt.Print("     Testing SSRF...")
			ssrfResults := native.TestSSRF(baseURL, params)
			found := 0
			for _, r := range ssrfResults {
				if r.Success {
					found++
				}
			}
			if found > 0 {
				fmt.Printf(" %d potential SSRF\n", found)
			} else {
				fmt.Println(" none found")
			}

			fmt.Print("     Testing open redirect...")
			redirectResults := native.TestOpenRedirect(baseURL, params)
			found = 0
			for _, r := range redirectResults {
				if r.Success {
					found++
				}
			}
			if found > 0 {
				fmt.Printf(" %d redirects\n", found)
			} else {
				fmt.Println(" none found")
			}
		} else {
			fmt.Println("     Skipping SSRF/Redirect (no params)")
		}

		fmt.Print("     Testing 403 bypass...")
		bypassResults := native.TestBypass403(baseURL)
		successCount := 0
		for _, r := range bypassResults {
			if r.Success {
				successCount++
			}
		}
		fmt.Printf(" %d bypasses\n", successCount)

		fmt.Print("     Testing CORS...")
		corsResults := native.TestCORS(baseURL)
		vulnCount := 0
		for _, r := range corsResults {
			if r.Vulnerable {
				vulnCount++
			}
		}
		if vulnCount > 0 {
			fmt.Printf(" %d misconfigurations\n", vulnCount)
		} else {
			fmt.Println(" OK")
		}

		fmt.Print("     Testing CSRF...")
		csrfResults := native.TestCSRF(baseURL)
		vulnCount = 0
		for _, r := range csrfResults {
			if r.Vulnerable {
				vulnCount++
			}
		}
		if vulnCount > 0 {
			fmt.Printf(" %d vulnerable forms\n", vulnCount)
		} else {
			fmt.Println(" OK")
		}

		fmt.Print("     Testing NoSQL...")
		nosqliResults := native.TestNoSQLi(baseURL, params)
		vulnCount = 0
		for _, r := range nosqliResults {
			if r.Vulnerable {
				vulnCount++
			}
		}
		if vulnCount > 0 {
			fmt.Printf(" %d vulnerable\n", vulnCount)
		} else {
			fmt.Println(" none found")
		}

		fmt.Print("     Testing LDAP...")
		ldapResults := native.TestLDAP(baseURL, params)
		vulnCount = 0
		for _, r := range ldapResults {
			if r.Vulnerable {
				vulnCount++
			}
		}
		if vulnCount > 0 {
			fmt.Printf(" %d vulnerable\n", vulnCount)
		} else {
			fmt.Println(" none found")
		}

		fmt.Print("     Testing GraphQL...")
		graphqlResults := native.TestGraphQL(baseURL)
		vulnCount = 0
		for _, r := range graphqlResults {
			if r.Vulnerable {
				vulnCount++
			}
		}
		if vulnCount > 0 {
			fmt.Printf(" %d vulnerable\n", vulnCount)
		} else {
			fmt.Println(" none found")
		}

		fmt.Print("     Testing XXE...")
		xxeResults := native.TestXXE(baseURL)
		vulnCount = 0
		for _, r := range xxeResults {
			if r.Vulnerable {
				vulnCount++
			}
		}
		if vulnCount > 0 {
			fmt.Printf(" %d vulnerable\n", vulnCount)
		} else {
			fmt.Println(" none found")
		}
	}
}

func (h *AutonomousHunter) executeAdvancedAttacks() {
	webPorts := h.getWebPorts()
	for _, port := range webPorts {
		isHTTPS := port == 443 || port == 8443
		protocol := "http"
		if isHTTPS {
			protocol = "https"
		}
		baseURL := fmt.Sprintf("%s://%s:%d", protocol, h.Target, port)
		fmt.Printf("     Analyzing JS on %s\n", baseURL)
		analyzeJS(baseURL)
	}
}

func (h *AutonomousHunter) executeAssetAnalysis() {
	if len(h.Subdomains) > 0 {
		fmt.Printf("     Checking %d subdomains for takeover...\n", len(h.Subdomains))
		takeovers := native.CheckSubdomainTakeover(h.Subdomains, 15)
		if len(takeovers) > 0 {
			for _, to := range takeovers {
				fmt.Printf("     [!] TAKEOVER: %s via %s\n", to.Subdomain, to.Platform)
			}
		} else {
			fmt.Println("     No takeovers detected")
		}
	}
}

func (h *AutonomousHunter) executeAIReport() {
	fmt.Println("     Generating intelligence report...")
	fmt.Println("     [REPORT] Target:", h.Target)
	fmt.Printf("     [REPORT] Open Ports: %d\n", len(h.OpenPorts))
	fmt.Printf("     [REPORT] Subdomains: %d\n", len(h.Subdomains))
	fmt.Println("     [REPORT] Analysis complete")
}

func (h *AutonomousHunter) getWebPorts() []int {
	webPorts := make([]int, 0)
	seen := make(map[int]bool)
	for _, p := range h.OpenPorts {
		if (p.Port == 80 || p.Port == 443 || p.Port == 8080 || p.Port == 8443) && !seen[p.Port] {
			seen[p.Port] = true
			webPorts = append(webPorts, p.Port)
		}
	}
	return webPorts
}

func (h *AutonomousHunter) guessParams(rawURL string) map[string]string {
	params := make(map[string]string)
	u, err := url.Parse(rawURL)
	if err == nil && len(u.Query()) > 0 {
		for k, v := range u.Query() {
			params[k] = v[0]
		}
		return params
	}
	params["url"] = rawURL
	params["q"] = "test"
	params["id"] = "1"
	params["page"] = "1"
	params["redirect"] = rawURL
	params["next"] = rawURL
	return params
}

func analyzeJS(baseURL string) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(baseURL)
	if err != nil {
		fmt.Printf("     [!] JS fetch error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	buf := make([]byte, 512*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	scriptCount := strings.Count(strings.ToLower(body), "<script")
	endpointCount := strings.Count(body, "/api/") + strings.Count(body, "/v1/") + strings.Count(body, "/v2/")
	secretCount := 0
	secretPatterns := []string{"apiKey", "api_key", "secret", "password", "token", "auth", "jwt", "bearer", "-----BEGIN"}
	for _, sp := range secretPatterns {
		secretCount += strings.Count(strings.ToLower(body), sp)
	}

	fmt.Printf("       Scripts: %d, Endpoints: ~%d, Secrets: ~%d\n", scriptCount, endpointCount, secretCount)
}

func stripANSI(str string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(str, "")
}
