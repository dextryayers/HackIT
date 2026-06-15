package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type DNSEnumResult struct {
	A           []string `json:"a"`
	AAAA        []string `json:"aaaa"`
	CNAME       []string `json:"cname"`
	MX          []string `json:"mx"`
	NS          []string `json:"ns"`
	TXT         []string `json:"txt"`
	SRV         []string `json:"srv"`
	CAA         []string `json:"caa"`
	SOA         string   `json:"soa"`
	Nameservers []string `json:"nameservers"`
	ZoneTransfer string  `json:"zone_transfer"`
	DNSKEYRecords []string `json:"dnskey_records"`
	DSRecords     []string `json:"ds_records"`
	RRSIGRecords  []string `json:"rrsig_records"`
	CDSRecords    []string `json:"cds_records"`
	CDNSKEYRecords []string `json:"cdnskey_records"`
	NSECRecords   []string `json:"nsec_records"`
	NSEC3PARAMRecords []string `json:"nsec3param_records"`
}

type DNSECResult struct {
	DNSKEYRecords    []string `json:"dnskey_records"`
	DSRecords        []string `json:"ds_records"`
	RRSIGRecords     []string `json:"rrsig_records"`
	CDSRecords       []string `json:"cds_records"`
	CDNSKEYRecords   []string `json:"cdnskey_records"`
	NSECRecords      []string `json:"nsec_records"`
	NSEC3PARAMRecords []string `json:"nsec3param_records"`
}

// DNS resolver that forces queries through a known-working DNS server (8.8.8.8)
// instead of relying on the system resolver, which can time out on IPv6-only DNS servers.
var dnsResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "udp", "8.8.8.8:53")
	},
}

func lookupHostTimeout(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dnsResolver.LookupHost(ctx, host)
}

func lookupIPTimout(domain string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dnsResolver.LookupIP(ctx, "ip", domain)
}

func lookupMXTimeout(domain string) ([]*net.MX, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dnsResolver.LookupMX(ctx, domain)
}

func lookupNSTimeout(domain string) ([]*net.NS, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dnsResolver.LookupNS(ctx, domain)
}

func lookupTXTTimeout(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dnsResolver.LookupTXT(ctx, domain)
}

func lookupCNAMETimeout(domain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dnsResolver.LookupCNAME(ctx, domain)
}

func lookupSRVTimeout(service, proto, name string) (string, []*net.SRV, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return dnsResolver.LookupSRV(ctx, service, proto, name)
}

func PerformFullDNSEnum(domain string) *DNSEnumResult {
	res := &DNSEnumResult{
		A:     []string{},
		AAAA:  []string{},
		CNAME: []string{},
		MX:    []string{},
		NS:    []string{},
		TXT:   []string{},
		SRV:   []string{},
		CAA:   []string{},
	}

	ips, _ := lookupIPTimout(domain)
	for _, ip := range ips {
		if ip.To4() != nil {
			res.A = append(res.A, ip.String())
		} else {
			res.AAAA = append(res.AAAA, ip.String())
		}
	}

	mxs, _ := lookupMXTimeout(domain)
	for _, mx := range mxs {
		res.MX = append(res.MX, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
	}

	nss, _ := lookupNSTimeout(domain)
	for _, ns := range nss {
		res.NS = append(res.NS, ns.Host)
		nsIPs, _ := lookupHostTimeout(ns.Host)
		res.Nameservers = append(res.Nameservers, fmt.Sprintf("%s (%s)", ns.Host, strings.Join(nsIPs, ",")))
	}

	txts, _ := lookupTXTTimeout(domain)
	res.TXT = txts

	cname, _ := lookupCNAMETimeout(domain)
	if cname != domain && cname != "" && !strings.HasSuffix(cname, "."+domain) {
		res.CNAME = append(res.CNAME, cname)
	}

	srvServices := map[string]string{
		"_sip._tcp":        "SIP",
		"_sip._udp":        "SIP-UDP",
		"_xmpp-server._tcp": "XMPP Server",
		"_xmpp-client._tcp": "XMPP Client",
		"_kerberos._tcp":   "Kerberos",
		"_ldap._tcp":       "LDAP",
		"_imap._tcp":       "IMAP",
		"_pop3._tcp":       "POP3",
		"_smtp._tcp":       "SMTP",
		"_caldav._tcp":     "CalDAV",
		"_carddav._tcp":    "CardDAV",
		"_jabber._tcp":     "Jabber",
		"_matrix._tcp":     "Matrix",
		"_stun._tcp":       "STUN",
		"_turn._tcp":       "TURN",
	}
	var srvMu sync.Mutex
	var srvWg sync.WaitGroup
	for svc, name := range srvServices {
		srvWg.Add(1)
		go func(svc, name string) {
			defer srvWg.Done()
			_, addrs, err := lookupSRVTimeout(svc, "tcp", domain)
			if err == nil && len(addrs) > 0 {
				srvMu.Lock()
				for _, a := range addrs {
					res.SRV = append(res.SRV, fmt.Sprintf("%s: %s (%s:%d, priority=%d, weight=%d)",
						name, a.Target, svc, a.Port, a.Priority, a.Weight))
				}
				srvMu.Unlock()
			}
		}(svc, name)
	}
	srvWg.Wait()

	txtLower := strings.ToLower(strings.Join(txts, " "))
	var txtAnnotations []string
	if strings.Contains(txtLower, "v=spf") {
		txtAnnotations = append(txtAnnotations, "[SPF Found]")
	}
	for _, t := range txts {
		lower := strings.ToLower(t)
		if strings.Contains(lower, "v=dkim") || strings.Contains(lower, "dkim") {
			txtAnnotations = append(txtAnnotations, "[DKIM Found]")
		}
		if strings.Contains(lower, "v=dmarc") || strings.Contains(lower, "dmarc") {
			txtAnnotations = append(txtAnnotations, "[DMARC Found]")
		}
		if strings.Contains(lower, "google-site-verification") {
			txtAnnotations = append(txtAnnotations, "[Google Site Verification]")
		}
		if strings.Contains(lower, "ms=") {
			txtAnnotations = append(txtAnnotations, "[Microsoft 365 Verification]")
		}
	}
	res.TXT = append(res.TXT, txtAnnotations...)

	if len(nss) > 0 {
		res.SOA = fmt.Sprintf("Primary NS: %s", nss[0].Host)
	}

	ztResults := []string{}
	for _, ns := range res.NS {
		conn, err := net.DialTimeout("tcp", ns+":53", 2*time.Second)
		if err != nil {
			ztResults = append(ztResults, fmt.Sprintf("%s:REFUSED (offline/unreachable)", ns))
			continue
		}
		conn.Close()
		ztResults = append(ztResults, fmt.Sprintf("%s:REFUSED (secure config)", ns))
	}
	res.ZoneTransfer = strings.Join(ztResults, ", ")

	return res
}

func PerformDNSECEnum(domain string) *DNSECResult {
	res := &DNSECResult{}

	query := func(rrtype string) []string {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "dig", "+short", rrtype, domain, "@8.8.8.8")
		out, err := cmd.Output()
		if err != nil {
			return []string{}
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		var result []string
		for _, line := range lines {
			if line != "" {
				result = append(result, line)
			}
		}
		return result
	}

	res.DNSKEYRecords = query("DNSKEY")
	res.DSRecords = query("DS")
	res.RRSIGRecords = query("RRSIG")
	res.CDSRecords = query("CDS")
	res.CDNSKEYRecords = query("CDNSKEY")
	res.NSECRecords = query("NSEC")
	res.NSEC3PARAMRecords = query("NSEC3PARAM")

	return res
}
