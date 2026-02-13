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

	fmt.Println("\n[+] Certificate:")
	if subject, ok := result.Certificate["subject"].(string); ok {
		fmt.Printf("    Subject: %s\n", subject)
	}
	if issuer, ok := result.Certificate["issuer"].(string); ok {
		fmt.Printf("    Issuer:  %s\n", issuer)
	}
	if validTo, ok := result.Certificate["valid_to"].(string); ok {
		fmt.Printf("    Expires: %s\n", validTo)
	}
	if days, ok := result.Certificate["days_remaining"].(int); ok {
		fmt.Printf("    Days Left: %d\n", days)
	}

	fmt.Println("\n[+] Protocols:")
	for proto, supported := range result.Protocols {
		status := "[NO]"
		if supported {
			status = "[YES]"
		}
		fmt.Printf("    %s %s\n", status, proto)
	}

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
