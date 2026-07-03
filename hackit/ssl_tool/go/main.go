package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var banner = `
  ╔════════════════════════════════════╗
  ║  <<  ADVANCED SSL TOOL SUITE  >>   ║
  ║  ────────────────────────────────  ║
  ║  • Deep SSL/TLS Scanner            ║
  ║  • Certificate Chain Analysis      ║
  ║  • Cipher & Crypto Audit           ║
  ║  • Vulnerability Detection         ║
  ║  • DNS Security Check              ║
  ║  • HTTP Headers Audit              ║
  ║  • Port Scanning                   ║
  ║  • Report Generation               ║
  ╚════════════════════════════════════╝
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--json" {
		runFlagMode()
		return
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print(banner)
	fmt.Println("\n  Example: google.com, 192.168.1.1:8443, detik.com:443")
	fmt.Println()

	for {
		fmt.Print("  Input Target: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println()
			fmt.Println("  [!] Exiting...")
			return
		}
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		if input == "exit" || input == "quit" || input == "q" {
			fmt.Println("  [!] Exiting...")
			return
		}

		host := input
		port := 443

		if strings.Contains(input, ":") {
			parts := strings.SplitN(input, ":", 2)
			host = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				p, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err == nil && p > 0 && p < 65536 {
					port = p
				}
			}
		}

		fmt.Printf("\n  [*] Scanning %s:%d...\n", host, port)
		start := time.Now()

		analyzer := NewAnalyzer(15, false)
		result := analyzer.Analyze(host, port)

		if result.Error != "" {
			fmt.Printf("\n  [!] Error: %s\n", result.Error)
			continue
		}

		result.Duration = time.Since(start)

		printGenReport(generateReport(
			host, result.Grade, result.Score, result.Duration,
			result.CertReport, result.CipherReport, result.VulnReport,
			result.TLSReport, result.DNSReport, result.HTTPReport,
			result.ChainReport, result.CryptoReport, result.PortReport,
		))

		fmt.Println("\n  Press Enter to scan another target, or type 'exit' to quit.")
	}
}

func runFlagMode() {
	var host string
	var port int
	var timeout int
	var outputFile string
	var fullScan bool

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
		case "-host", "--host":
			if i+1 < len(args) {
				host = args[i+1]
				i++
			}
		case "-port", "--port":
			if i+1 < len(args) {
				port, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-timeout", "--timeout":
			if i+1 < len(args) {
				timeout, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-output", "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "-full", "--full":
			fullScan = true
		}
	}

	if host == "" {
		fmt.Println("  Usage: worker --json -host <host> [-port 443] [-timeout 15] [-full] [-output file.json]")
		os.Exit(1)
	}
	if port == 0 {
		port = 443
	}
	if timeout == 0 {
		timeout = 15
	}

	start := time.Now()
	analyzer := NewAnalyzer(timeout, fullScan)
	result := analyzer.Analyze(host, port)
	result.Duration = time.Since(start)

	if result.Error != "" {
		fmt.Printf(`{"error":"%s"}`, result.Error)
		os.Exit(1)
	}

	report := generateReport(host, result.Grade, result.Score, result.Duration,
		result.CertReport, result.CipherReport, result.VulnReport,
		result.TLSReport, result.DNSReport, result.HTTPReport,
		result.ChainReport, result.CryptoReport, result.PortReport)

	jsonData, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(jsonData))

	if outputFile != "" {
		os.WriteFile(outputFile, jsonData, 0644)
	}
}

func printGenReport(r GenReport) {
	gradeColor := "\033[32m"
	switch r.Grade {
	case "A", "A-":
		gradeColor = "\033[32m"
	case "B+", "B", "C+", "C":
		gradeColor = "\033[33m"
	case "D+", "D":
		gradeColor = "\033[31m"
	case "F":
		gradeColor = "\033[31;1m"
	}

	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Printf("\n  SSL TOOL — ADVANCED SECURITY REPORT")
	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Printf("\n  Target    : \033[1m%s\033[0m", r.Target)
	fmt.Printf("\n  Grade     : %s%s\033[0m  (%d/100)", gradeColor, r.Grade, r.Score)
	fmt.Printf("\n  Duration  : %s", r.Duration)
	fmt.Printf("\n  Issues    : %d total", len(r.AllIssues))
	fmt.Printf("\n%s", strings.Repeat("-", 60))

	if r.Cert.SubjectCN != "" {
		fmt.Printf("\n  [+] Certificate: %s", r.Cert.SubjectCN)
		fmt.Printf("\n      Issuer     : %s", r.Cert.IssuerCN)
		fmt.Printf("\n      Expires    : %d days", r.Cert.DaysRemaining)
		fmt.Printf("\n      Key        : %d-bit %s (%s)", r.Cert.KeyBits, r.Cert.KeyType, r.Cert.KeyStrength)
		fmt.Printf("\n      SANs       : %d entries", r.Cert.SanCount)
		fmt.Printf("\n      Chain OK   : %v", r.Cert.ChainValid)
	}

	fmt.Printf("\n  [+] Ciphers : %d supported, PFS=%v", r.Ciphers.TotalCiphers, r.Ciphers.PFSEnabled)
	fmt.Printf("\n      Best    : %s", r.Ciphers.BestCipher)

	if r.Vulns.Count > 0 {
		fmt.Printf("\n  [+] Vulns   : %d active", r.Vulns.Count)
	}
	fmt.Printf("\n  [+] TLS     : %s, h2=%v", strings.Join(r.TLS.Protocols, ", "), r.TLS.H2)

	if r.DNS.SPFRecord != "" || r.DNS.DMARC != "" {
		fmt.Printf("\n  [+] DNS     : SPF=%v DMARC=%v DKIM=%v",
			r.DNS.SPFRecord != "", r.DNS.DMARC != "", r.DNS.DKIMDetect)
	}

	if r.HTTP.HSTS != "" || r.HTTP.CSP != "" {
		fmt.Printf("\n  [+] HTTP    : HSTS=%v CSP=%v XFO=%v",
			r.HTTP.HSTS != "", r.HTTP.CSP != "", r.HTTP.XFrameOptions != "")
	}

	if r.Ports.TotalOpen > 0 {
		fmt.Printf("\n  [+] Ports   : %d open", r.Ports.TotalOpen)
	}

	if len(r.Recommendations) > 0 {
		fmt.Printf("\n%s", strings.Repeat("-", 60))
		fmt.Printf("\n  RECOMMENDATIONS:")
		maxRecs := 8
		if len(r.Recommendations) < maxRecs {
			maxRecs = len(r.Recommendations)
		}
		for i := 0; i < maxRecs; i++ {
			rc := "\033[33m"
			if strings.HasPrefix(r.Recommendations[i], "RENEW") || strings.HasPrefix(r.Recommendations[i], "REPLACE") {
				rc = "\033[31m"
			} else if strings.HasPrefix(r.Recommendations[i], "ENABLE") || strings.HasPrefix(r.Recommendations[i], "CONFIGURE") {
				rc = "\033[32m"
			}
			fmt.Printf("\n    %s• %s\033[0m", rc, r.Recommendations[i])
		}
	}

	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Println()
}
