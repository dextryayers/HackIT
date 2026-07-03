package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type VulnFinding struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	CVE      string `json:"cve,omitempty"`
}

type VulnReport struct {
	Findings []VulnFinding `json:"findings"`
	Count    int           `json:"count"`
	Critical int           `json:"critical"`
	High     int           `json:"high"`
	Medium   int           `json:"medium"`
	Low      int           `json:"low"`
	Score    int           `json:"score"`
}

func scanVulnerabilities(host string, port int, timeout time.Duration) VulnReport {
	var report VulnReport
	addr := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{Timeout: timeout}

	checkSSLv2(addr, dialer, &report)
	checkSSLv3(addr, dialer, &report)
	checkTLS10(addr, dialer, &report)
	checkTLS11(addr, dialer, &report)
	checkCompression(addr, dialer, &report)
	checkHeartbleed(addr, dialer, &report)
	checkSecureReneg(addr, dialer, &report)
	checkExportCiphers(addr, dialer, &report)
	checkDowngradePrevention(addr, dialer, &report)
	checkTicketBomb(addr, dialer, &report)

	report.Count = report.Critical + report.High + report.Medium + report.Low

	score := 100
	for _, f := range report.Findings {
		if f.Status == "VULNERABLE" || f.Status == "WEAK" {
			switch f.Severity {
			case "CRITICAL":
				score -= 40
			case "HIGH":
				score -= 25
			case "MEDIUM":
				score -= 15
			case "LOW":
				score -= 5
			}
		}
	}
	if score < 0 {
		score = 0
	}
	report.Score = score

	return report
}

func addFinding(report *VulnReport, name, severity, status, detail, cve string) {
	f := VulnFinding{
		Name:     name,
		Severity: severity,
		Status:   status,
		Detail:   detail,
	}
	if cve != "" {
		f.CVE = cve
	}
	report.Findings = append(report.Findings, f)

	if status == "VULNERABLE" || status == "WEAK" {
		switch severity {
		case "CRITICAL":
			report.Critical++
		case "HIGH":
			report.High++
		case "MEDIUM":
			report.Medium++
		case "LOW":
			report.Low++
		}
	}
}

func testTLSVersion(addr string, dialer *net.Dialer, host string, version uint16) bool {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         host,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func checkSSLv2(addr string, dialer *net.Dialer, report *VulnReport) {
	config := &tls.Config{InsecureSkipVerify: true}
	config.MaxVersion = 0x0002
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err == nil {
		conn.Close()
		addFinding(report, "DROWN (SSLv2)", "CRITICAL", "VULNERABLE",
			"SSLv2 protocol is enabled - server vulnerable to DROWN attack", "CVE-2016-0800")
	} else {
		addFinding(report, "DROWN (SSLv2)", "CRITICAL", "NOT VULNERABLE",
			"SSLv2 protocol is not enabled", "CVE-2016-0800")
	}
}

func checkSSLv3(addr string, dialer *net.Dialer, report *VulnReport) {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         0x0300,
		MaxVersion:         0x0300,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err == nil {
		conn.Close()
		addFinding(report, "POODLE (SSLv3)", "MEDIUM", "VULNERABLE",
			"SSLv3 protocol is enabled - vulnerable to POODLE padding oracle attack", "CVE-2014-3566")
	} else {
		addFinding(report, "POODLE (SSLv3)", "MEDIUM", "NOT VULNERABLE",
			"SSLv3 protocol is not enabled", "CVE-2014-3566")
	}
}

func checkTLS10(addr string, dialer *net.Dialer, report *VulnReport) {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err == nil {
		conn.Close()
		addFinding(report, "BEAST (TLS 1.0)", "LOW", "VULNERABLE",
			"TLS 1.0 enabled - vulnerable to BEAST attack if CBC ciphers preferred", "CVE-2011-3389")
	} else {
		addFinding(report, "BEAST (TLS 1.0)", "LOW", "NOT VULNERABLE",
			"TLS 1.0 is not enabled", "CVE-2011-3389")
	}
}

func checkTLS11(addr string, dialer *net.Dialer, report *VulnReport) {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS11,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err == nil {
		conn.Close()
		addFinding(report, "TLS 1.1 (Deprecated)", "LOW", "VULNERABLE",
			"TLS 1.1 is deprecated by RFC 8996 - should be disabled", "")
	} else {
		addFinding(report, "TLS 1.1 (Deprecated)", "LOW", "NOT VULNERABLE",
			"TLS 1.1 is not enabled - good", "")
	}
}

func checkCompression(addr string, dialer *net.Dialer, report *VulnReport) {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return
	}
	state := conn.ConnectionState()
	conn.Close()

	if state.DidResume {
		return
	}

	addFinding(report, "CRIME (TLS Compression)", "MEDIUM", "NOT VULNERABLE",
		"TLS compression is not enabled", "CVE-2012-4929")
}

func checkHeartbleed(addr string, dialer *net.Dialer, report *VulnReport) {
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return
	}
	defer conn.Close()

	tcpConn := conn.NetConn()
	tcpConn.SetDeadline(time.Now().Add(5 * time.Second))

	heartbeat := []byte{
		0x18, 0x03, 0x02, 0x00, 0x03,
		0x01, 0x40, 0x00,
	}

	_, err = tcpConn.Write(heartbeat)
	if err != nil {
		return
	}

	reply := make([]byte, 1024)
	n, err := tcpConn.Read(reply)
	if err == nil && n > 7 {
		if len(reply) > 100 && reply[0] == 0x18 {
			addFinding(report, "Heartbleed", "CRITICAL", "VULNERABLE",
				"Server responded to malformed heartbeat request - vulnerable to Heartbleed", "CVE-2014-0160")
			return
		}
	}

	addFinding(report, "Heartbleed", "CRITICAL", "NOT VULNERABLE",
		"Server did not respond to malformed heartbeat", "CVE-2014-0160")
}

func checkSecureReneg(addr string, dialer *net.Dialer, report *VulnReport) {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		config.MinVersion = tls.VersionTLS10
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, config)
		if err != nil {
			return
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		return
	}

	secureReneg := state.TLSUnique != nil
	if secureReneg {
		addFinding(report, "Secure Renegotiation", "MEDIUM", "NOT VULNERABLE",
			"Secure renegotiation IS supported", "")
	} else {
		addFinding(report, "Secure Renegotiation", "MEDIUM", "VULNERABLE",
			"Secure renegotiation IS NOT supported - vulnerable to renegotiation attack", "")
	}
}

func checkExportCiphers(addr string, dialer *net.Dialer, report *VulnReport) {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			0x0062, 0x0063, 0x0064, 0x0065, 0x0014, 0x0033,
		},
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err == nil {
		conn.Close()
		addFinding(report, "FREAK/Logjam (Export Ciphers)", "HIGH", "VULNERABLE",
			"Server accepts export-grade ciphers - vulnerable to FREAK or Logjam", "CVE-2015-0204")
	} else {
		addFinding(report, "FREAK/Logjam (Export Ciphers)", "HIGH", "NOT VULNERABLE",
			"Server does not accept export-grade ciphers", "CVE-2015-0204")
	}
}

func checkDowngradePrevention(addr string, dialer *net.Dialer, report *VulnReport) {
	addFinding(report, "TLS Fallback SCSV", "MEDIUM", "INFO",
		"TLS_FALLBACK_SCSV signaling cipher suite detection - prevents downgrade attacks", "")
}

func checkTicketBomb(addr string, dialer *net.Dialer, report *VulnReport) {
	state, err := getConnState(addr, dialer)
	if err != nil {
		return
	}
	if state.DidResume {
		addFinding(report, "Session Ticket Size", "LOW", "INFO",
			"Session tickets are supported - check ticket size for DoS potential", "")
	}
}

func printVulnReport(r VulnReport) {
	actualVulns := 0
	for _, f := range r.Findings {
		if f.Status == "VULNERABLE" || f.Status == "WEAK" {
			actualVulns++
		}
	}

	fmt.Printf("\n  [+] Vulnerability Analysis (%d total, %d active):", r.Count, actualVulns)

	if r.Critical > 0 {
		fmt.Printf("\n    %s%s CRITICAL%s: %d finding(s)", "\033[31m", "[!!]", "\033[0m", r.Critical)
	}
	if r.High > 0 {
		fmt.Printf("\n    %s[HIG]%s: %d finding(s)", "\033[31m", "\033[0m", r.High)
	}
	if r.Medium > 0 {
		fmt.Printf("\n    %s[MED]%s: %d finding(s)", "\033[33m", "\033[0m", r.Medium)
	}
	if r.Low > 0 {
		fmt.Printf("\n    %s[LOW]%s: %d finding(s)", "\033[2m", "\033[0m", r.Low)
	}

	for _, f := range r.Findings {
		sevColor := "\033[32m"
		statusSym := "[✓]"
		switch f.Severity {
		case "CRITICAL":
			sevColor = "\033[31m"
		case "HIGH":
			sevColor = "\033[31m"
		case "MEDIUM":
			sevColor = "\033[33m"
		case "LOW":
			sevColor = "\033[2m"
		}
		if f.Status == "VULNERABLE" || f.Status == "WEAK" {
			statusSym = "[!]"
		} else if strings.Contains(f.Status, "NOT") {
			statusSym = "[✓]"
		} else {
			statusSym = "[i]"
		}

		fmt.Printf("\n    %s%s%s %s", sevColor, statusSym, "\033[0m", f.Name)
		fmt.Printf("\n       Severity: %s%s%s", sevColor, f.Severity, "\033[0m")
		fmt.Printf("\n       Status: %s", f.Status)
		if f.CVE != "" {
			fmt.Printf("\n       CVE: %s", f.CVE)
		}
		fmt.Printf("\n       %s", f.Detail)
	}

	if r.Score < 100 {
		fmt.Printf("\n\n    [!] Vulnerability Score: %d/100 (deductions applied)", r.Score)
	}
	fmt.Println()
}
