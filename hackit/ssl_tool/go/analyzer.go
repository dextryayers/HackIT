package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Host          string            `json:"host"`
	Port          int               `json:"port"`
	StartTime     time.Time         `json:"-"`
	Duration      time.Duration     `json:"-"`
	CertReport    CertReport        `json:"certificate"`
	CipherReport  CipherReport      `json:"ciphers"`
	VulnReport    VulnReport        `json:"vulnerabilities"`
	TLSReport     TLSFeatureReport  `json:"tls_features"`
	DNSReport     DNSReport         `json:"dns"`
	HTTPReport    HTTPReport        `json:"http"`
	ChainReport   ChainReport       `json:"chain"`
	CryptoReport  CryptoReport      `json:"crypto"`
	PortReport    PortScanReport    `json:"port_scan"`
	Protocols     []string          `json:"protocols"`
	Grade         string            `json:"grade"`
	Score         int               `json:"score"`
	Issues        []string          `json:"issues"`
	Error         string            `json:"error,omitempty"`
}

type Analyzer struct {
	Timeout time.Duration
	Full    bool
}

func NewAnalyzer(timeout int, full bool) *Analyzer {
	return &Analyzer{
		Timeout: time.Duration(timeout) * time.Second,
		Full:    full,
	}
}

func (a *Analyzer) Analyze(host string, port int) Result {
	res := Result{
		Host:      host,
		Port:      port,
		StartTime: time.Now(),
	}
	deadline := time.Now().Add(a.Timeout)

	addr := resolveAddr(host, port)
	dialer := &net.Dialer{Timeout: a.Timeout}

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		res.Error = fmt.Sprintf("Connection failed: %v", err)
		return res
	}

	cert := conn.ConnectionState().PeerCertificates[0]
	chain := conn.ConnectionState().PeerCertificates
	conn.Close()

	res.CertReport = analyzeCertificate(cert, chain)
	res.ChainReport = scanChain(cert, chain)

	useHost := host
	usePort := port
	if net.ParseIP(host) == nil {
		parts := strings.SplitN(addr, ":", 2)
		if len(parts) == 2 {
			useHost = parts[0]
		}
	}

	var wg sync.WaitGroup

	heavyTimeout := time.Until(deadline)
	if heavyTimeout < 6*time.Second {
		heavyTimeout = 6 * time.Second
	}

	wg.Add(4)
	go func() {
		defer wg.Done()
		res.CipherReport = scanCiphers(useHost, usePort, heavyTimeout)
		if a.Full {
			legacy := scanWeakCiphersLegacy(useHost, usePort, heavyTimeout)
			res.CipherReport.Supported = append(res.CipherReport.Supported, legacy.Supported...)
			res.CipherReport.Insecure = append(res.CipherReport.Insecure, legacy.Insecure...)
			res.CipherReport.TotalCiphers = len(res.CipherReport.Supported)
		}
	}()
	go func() {
		defer wg.Done()
		res.VulnReport = scanVulnerabilities(useHost, usePort, heavyTimeout)
	}()
	go func() {
		defer wg.Done()
		res.TLSReport = simulateTLS(useHost, usePort, heavyTimeout)
		res.Protocols = res.TLSReport.Protocols
	}()
	go func() {
		defer wg.Done()
		res.CryptoReport = scanCrypto(useHost, usePort, heavyTimeout)
	}()
	wg.Wait()

	lightTimeout := time.Until(deadline)
	if lightTimeout < 4*time.Second {
		lightTimeout = 4 * time.Second
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		res.DNSReport = scanDNS(host, lightTimeout)
	}()
	go func() {
		defer wg.Done()
		res.HTTPReport = scanHTTP(useHost, usePort, lightTimeout)
	}()
	go func() {
		defer wg.Done()
		res.PortReport = scanPorts(host, useHost, lightTimeout)
	}()
	wg.Wait()

	res.Score = calculateFinalGrade(res.CertReport, res.CipherReport, res.VulnReport, res.TLSReport)
	res.Grade = calculateGrade(res.Score)

	allIssues := collectAllIssues(res.CertReport, res.CipherReport, res.VulnReport, res.TLSReport)
	allIssues = append(allIssues, res.DNSReport.Issues...)
	allIssues = append(allIssues, res.HTTPReport.Issues...)
	allIssues = append(allIssues, res.ChainReport.Issues...)
	allIssues = append(allIssues, res.CryptoReport.Issues...)
	allIssues = append(allIssues, res.PortReport.Issues...)
	res.Issues = allIssues

	res.Duration = time.Since(res.StartTime)

	return res
}

func resolveAddr(host string, port int) string {
	if net.ParseIP(host) != nil {
		return fmt.Sprintf("%s:%d", host, port)
	}

	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				return fmt.Sprintf("%s:%d", ipv4.String(), port)
			}
		}
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func printResult(r Result) {
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
	fmt.Printf("\n  SSL/TLS DEEP ANALYSIS RESULTS")
	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Printf("\n  Host      : %s:%d", r.Host, r.Port)
	fmt.Printf("\n  Grade     : %s%s\033[0m  (%d/100)", gradeColor, r.Grade, r.Score)
	fmt.Printf("\n  Speed     : %dms", r.Duration.Milliseconds())
	fmt.Printf("\n%s", strings.Repeat("-", 60))

	printCertReport(r.CertReport)
	printChainReport(r.ChainReport)
	printCipherReport(r.CipherReport)
	printVulnReport(r.VulnReport)
	printTLSFeatures(r.TLSReport)
	printDNSReport(r.DNSReport)
	printHTTPReport(r.HTTPReport)
	printCryptoReport(r.CryptoReport)
	printPortReport(r.PortReport)

	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Printf("\n  Scan Complete -- %d total findings", len(r.Issues))
	fmt.Printf("\n    %d Certificate Issues", len(r.CertReport.Issues))
	fmt.Printf("\n    %d Chain Issues", len(r.ChainReport.Issues))
	fmt.Printf("\n    %d Weak + %d Broken Ciphers", len(r.CipherReport.Weak), len(r.CipherReport.Insecure))
	fmt.Printf("\n    %d Vulnerabilities (%d critical, %d high, %d medium, %d low)",
		r.VulnReport.Count, r.VulnReport.Critical, r.VulnReport.High,
		r.VulnReport.Medium, r.VulnReport.Low)
	fmt.Printf("\n    %d TLS Feature Issues", len(r.TLSReport.Issues))
	fmt.Printf("\n    %d DNS Issues", len(r.DNSReport.Issues))
	fmt.Printf("\n    %d HTTP Issues", len(r.HTTPReport.Issues))
	fmt.Printf("\n    %d Crypto Issues", len(r.CryptoReport.Issues))
	fmt.Printf("\n    %d Port Issues", len(r.PortReport.Issues))
	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Println()
}
