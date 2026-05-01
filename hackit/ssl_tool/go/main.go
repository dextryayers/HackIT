package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

var (
	host       string
	port       int
	timeout    int
	outputFile string
)

func main() {
	flag.StringVar(&host, "host", "", "Target Host")
	flag.IntVar(&port, "port", 443, "Target Port")
	flag.IntVar(&timeout, "timeout", 10, "Timeout in seconds")
	flag.StringVar(&outputFile, "output", "", "Save results to JSON file")
	flag.Parse()

	if host == "" {
		fmt.Println("Error: --host is required")
		os.Exit(1)
	}

	fmt.Printf("[*] Analyzing %s:%d...\n", host, port)

	analyzer := NewAnalyzer(timeout)
	result := analyzer.Analyze(host, port)

	if result.Error != "" {
		fmt.Printf("[!] Error: %s\n", result.Error)
		os.Exit(1)
	}

	fmt.Printf("\n[+] Security Grade: %s\n", result.Grade)

	fmt.Printf("\n[+] Certificate Detail:\n")
	if cn, ok := result.Certificate["common_name"].(string); ok {
		fmt.Printf("    %-15s : %s\n", "Common Name", cn)
	}
	if issuer, ok := result.Certificate["issuer"].(string); ok {
		fmt.Printf("    %-15s : %s\n", "Issuer", issuer)
	}
	if validTo, ok := result.Certificate["valid_to"].(string); ok {
		fmt.Printf("    %-15s : %s\n", "Expiry Date", validTo)
	}
	if days, ok := result.Certificate["days_remaining"].(int); ok {
		color := "\033[32m"
		if days < 30 { color = "\033[33m" }
		if days < 0 { color = "\033[31m" }
		fmt.Printf("    %-15s : %s%d days%s\n", "Life Remaining", color, days, "\033[0m")
	}
	if keyAlg, ok := result.Certificate["key_alg"].(string); ok {
		fmt.Printf("    %-15s : %s\n", "Public Key", keyAlg)
	}
	if sigAlg, ok := result.Certificate["signature_alg"].(string); ok {
		fmt.Printf("    %-15s : %s\n", "Signature", sigAlg)
	}

	if san, ok := result.Certificate["san"].([]string); ok && len(san) > 0 {
		fmt.Printf("\n[+] Subject Alternative Names (SAN):\n")
		for _, name := range san {
			fmt.Printf("    - %s\n", name)
		}
	}

	if len(result.Chain) > 0 {
		fmt.Printf("\n[+] Trust Chain Mapping:\n")
		for i, c := range result.Chain {
			prefix := "    └── "
			if i == 0 { prefix = "    [0] " }
			fmt.Printf("%s%s (Issuer: %s)\n", prefix, c["subject"], c["issuer"])
		}
	}

	fmt.Println("\n[+] Protocol Support Mapping:")
	protocols := []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}
	for _, proto := range protocols {
		supported, exists := result.Protocols[proto]
		if !exists { continue }
		
		status := "\033[31m[NO]\033[0m "
		color := "\033[31m"
		if supported {
			status = "\033[32m[YES]\033[0m"
			color = "\033[32m"
			if proto == "TLS 1.1" || proto == "TLS 1.0" {
				color = "\033[33m" // Warning for legacy
			}
		}
		fmt.Printf("    %s %s%-10s%s\n", status, color, proto, "\033[0m")
	}

	if len(result.ALPN) > 0 {
		fmt.Printf("\n[+] ALPN Negotiated Protocols:\n")
		for _, proto := range result.ALPN {
			fmt.Printf("    - %s\n", proto)
		}
	}

	if len(result.Ciphers) > 0 {
		fmt.Printf("\n[+] Supported Cipher Suites:\n")
		for _, cipher := range result.Ciphers {
			fmt.Printf("    - %s\n", cipher)
		}
	}

	fmt.Printf("\n[+] Advanced TLS Features:\n")
	ocspStatus := "\033[31m[NO]\033[0m"
	if result.OCSPStapled { ocspStatus = "\033[32m[YES]\033[0m" }
	fmt.Printf("    %-20s : %s\n", "OCSP Stapling", ocspStatus)

	renegStatus := "\033[31m[NO]\033[0m"
	if result.SecureReneg { renegStatus = "\033[32m[YES]\033[0m" }
	fmt.Printf("    %-20s : %s\n", "Secure Renegotiation", renegStatus)

	if len(result.Issues) > 0 {
		fmt.Println("\n[!] Issues Found:")
		for _, issue := range result.Issues {
			fmt.Printf("    - %s\n", issue)
		}
	} else {
		fmt.Println("\n[✓] No major issues found.")
	}

	if outputFile != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Printf("Error saving results: %v\n", err)
		} else {
			err = os.WriteFile(outputFile, data, 0644)
			if err != nil {
				fmt.Printf("Error writing file: %v\n", err)
			} else {
				fmt.Printf("[+] Results saved to %s\n", outputFile)
			}
		}
	}
}
