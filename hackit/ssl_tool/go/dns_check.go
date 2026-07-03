package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type DNSReport struct {
	ARecords   []string `json:"a_records"`
	AAAARecords []string `json:"aaaa_records"`
	MXRecords  []string `json:"mx_records"`
	NSServers  []string `json:"ns_servers"`
	SOARecord  string   `json:"soa_record"`
	PTRRecord  string   `json:"ptr_record"`
	CAA        string   `json:"caa"`
	SPFRecord  string   `json:"spf"`
	DKIMDetect bool     `json:"dkim_detect"`
	DMARC      string   `json:"dmarc"`
	DNSSEC     bool     `json:"dnssec"`
	Issues     []string `json:"issues"`
	Score      int      `json:"score"`
}

func scanDNS(host string, timeout time.Duration) DNSReport {
	r := DNSReport{
		ARecords:   make([]string, 0),
		AAAARecords: make([]string, 0),
		MXRecords:  make([]string, 0),
		NSServers:  make([]string, 0),
		Issues:     make([]string, 0),
	}
	dnsTimeout := timeout
	if dnsTimeout > 8*time.Second {
		dnsTimeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	resolver := net.Resolver{}

	ips, _ := resolver.LookupIPAddr(ctx, host)
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			r.ARecords = append(r.ARecords, ip.IP.String())
		} else {
			r.AAAARecords = append(r.AAAARecords, ip.IP.String())
		}
	}

	mxs, _ := resolver.LookupMX(ctx, host)
	for _, mx := range mxs {
		r.MXRecords = append(r.MXRecords, fmt.Sprintf("%s (prio %d)", mx.Host, mx.Pref))
	}

	ns, _ := resolver.LookupNS(ctx, host)
	for _, n := range ns {
		r.NSServers = append(r.NSServers, n.Host)
	}

	soa, _ := resolver.LookupTXT(ctx, getSOAHost(host))
	if len(soa) > 0 {
		r.SOARecord = soa[0]
	}

	addrs, _ := net.LookupAddr(host)
	if len(addrs) > 0 {
		r.PTRRecord = addrs[0]
	}

	txts, _ := resolver.LookupTXT(ctx, host)
	for _, t := range txts {
		up := strings.ToUpper(t)
		if strings.HasPrefix(up, "V=SPF") {
			r.SPFRecord = t
		}
		if strings.HasPrefix(up, "V=DMARC") {
			r.DMARC = t
		}
	}

	caaTxt, _ := resolver.LookupTXT(ctx, "_cname."+host)
	_ = caaTxt

	caaRecords, _ := resolver.LookupTXT(ctx, host)
	for _, t := range caaRecords {
		up := strings.ToUpper(t)
		if strings.Contains(up, "CAA") || strings.HasPrefix(up, "0 ISSUE") || strings.HasPrefix(up, "0 ISSUEWILD") {
			r.CAA = t
		}
	}

	dkimSelectors := []string{"default", "google", "selector1", "selector2", "dkim", "mail"}
	for _, sel := range dkimSelectors {
		dkimDomain := fmt.Sprintf("%s._domainkey.%s", sel, host)
		dkim, _ := resolver.LookupTXT(ctx, dkimDomain)
		if len(dkim) > 0 {
			r.DKIMDetect = true
			break
		}
	}

	dnskey, _ := resolver.LookupTXT(ctx, host)
	for _, t := range dnskey {
		if strings.Contains(t, "DNSKEY") || strings.HasPrefix(strings.ToUpper(t), "DNSKEY") {
			r.DNSSEC = true
			break
		}
	}

	r.Issues = buildDNSIssues(&r)
	r.Score = calcDNSScore(&r)
	return r
}

func getSOAHost(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func buildDNSIssues(r *DNSReport) []string {
	var issues []string
	if len(r.ARecords) == 0 && len(r.AAAARecords) == 0 {
		issues = append(issues, "No A/AAAA records found - host may not resolve")
	}
	if r.SPFRecord == "" {
		issues = append(issues, "No SPF record found - email spoofing protection missing")
	}
	if r.DMARC == "" {
		issues = append(issues, "No DMARC record found - email authentication policy missing")
	}
	if !r.DKIMDetect {
		issues = append(issues, "No DKIM record detected - email signing not configured")
	}
	if r.CAA == "" {
		issues = append(issues, "No CAA record found - no CA authorization policy")
	}
	if !r.DNSSEC {
		issues = append(issues, "DNSSEC not detected - DNS spoofing protection missing")
	}
	if len(r.MXRecords) == 0 {
		issues = append(issues, "No MX records - email delivery may be misconfigured")
	}
	return issues
}

func calcDNSScore(r *DNSReport) int {
	s := 100
	if r.SPFRecord == "" {
		s -= 15
	}
	if r.DMARC == "" {
		s -= 15
	}
	if !r.DKIMDetect {
		s -= 10
	}
	if r.CAA == "" {
		s -= 10
	}
	if !r.DNSSEC {
		s -= 10
	}
	if len(r.ARecords) == 0 && len(r.AAAARecords) == 0 {
		s = 0
	}
	if s < 0 {
		s = 0
	}
	return s
}

func printDNSReport(r DNSReport) {
	fmt.Printf("\n  [+] DNS Security Analysis:")
	fmt.Printf("\n    %-24s : %v", "A Records", len(r.ARecords))
	fmt.Printf("\n    %-24s : %v", "AAAA Records", len(r.AAAARecords))
	fmt.Printf("\n    %-24s : %v", "MX Records", len(r.MXRecords))
	fmt.Printf("\n    %-24s : %v", "NS Servers", len(r.NSServers))
	if r.PTRRecord != "" {
		fmt.Printf("\n    %-24s : %s", "PTR Record", r.PTRRecord)
	}
	if r.SPFRecord != "" {
		fmt.Printf("\n    %-24s : %s", "SPF Record", truncateStr(r.SPFRecord, 60))
	}
	if r.DMARC != "" {
		fmt.Printf("\n    %-24s : %s", "DMARC Record", truncateStr(r.DMARC, 60))
	}
	fmt.Printf("\n    %-24s : %v", "DKIM Detected", r.DKIMDetect)
	fmt.Printf("\n    %-24s : %v", "DNSSEC", r.DNSSEC)
	fmt.Printf("\n    %-24s : %d/100", "DNS Score", r.Score)
	if len(r.Issues) > 0 {
		fmt.Printf("\n\n    [!] DNS Issues (%d):", len(r.Issues))
		for _, iss := range r.Issues {
			fmt.Printf("\n      - %s", iss)
		}
	}
	fmt.Println()
}
