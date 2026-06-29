package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SRVRecord struct {
	Service  string `json:"service"`
	Proto    string `json:"proto"`
	Name     string `json:"name"`
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
}

type MXRecord struct {
	Host     string `json:"host"`
	Preference int  `json:"preference"`
}

type CTLogEntry struct {
	IssuerCaID  int    `json:"issuer_ca_id"`
	IssuerName  string `json:"issuer_name"`
	CommonName  string `json:"common_name"`
	NameValue   string `json:"name_value"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
}

type PassiveIntel struct {
	SRVRecords []SRVRecord  `json:"srv_records"`
	MXRecords  []MXRecord   `json:"mx_records"`
	CTLogs     []CTLogEntry `json:"ct_logs"`
	CacheSnoop []string     `json:"cache_snoop"`
	Subdomains []string     `json:"subdomains"`
}

var passiveIntelPool = sync.Pool{
	New: func() interface{} { return &PassiveIntel{} },
}

func RunPassiveScan(host string) PassiveIntel {
	intel := PassiveIntel{
		SRVRecords: []SRVRecord{},
		MXRecords:  []MXRecord{},
		CTLogs:     []CTLogEntry{},
		CacheSnoop: []string{},
		Subdomains: []string{},
	}

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		intel.SRVRecords = enumerateSRV(host)
	}()

	go func() {
		defer wg.Done()
		intel.MXRecords = enumerateMX(host)
	}()

	go func() {
		defer wg.Done()
		intel.CTLogs = queryCTLogs(host)
	}()

	go func() {
		defer wg.Done()
		intel.CacheSnoop = dnsCacheSnoop(host)
	}()

	wg.Wait()

	subdomains := make(map[string]bool)
	for _, ct := range intel.CTLogs {
		for _, name := range strings.Split(ct.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if name != "" && strings.HasSuffix(name, "."+host) {
				subdomains[name] = true
			}
		}
	}
	for _, srv := range intel.SRVRecords {
		if srv.Target != "" && strings.HasSuffix(srv.Target, "."+host) {
			subdomains[srv.Target] = true
		}
	}
	for s := range subdomains {
		intel.Subdomains = append(intel.Subdomains, s)
	}

	return intel
}

func enumerateSRV(domain string) []SRVRecord {
	services := []string{
		"_sip._tcp", "_sip._udp", "_sips._tcp",
		"_xmpp-client._tcp", "_xmpp-server._tcp",
		"_imap._tcp", "_imaps._tcp",
		"_pop3._tcp", "_pop3s._tcp",
		"_ldap._tcp", "_kerberos._tcp",
		"_http._tcp", "_https._tcp",
		"_caldav._tcp", "_caldavs._tcp",
		"_carddav._tcp", "_carddavs._tcp",
		"_jabber._tcp", "_jabber._udp",
		"_mongodb._tcp", "_mysql._tcp",
		"_postgresql._tcp", "_redis._tcp",
		"_docker._tcp", "_etcd._tcp",
		"_consul._tcp", "_vault._tcp",
	}
	var records []SRVRecord
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := net.Resolver{}
	for _, svc := range services {
		_, addrs, err := resolver.LookupSRV(ctx, "", "", svc+"."+domain)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			parts := strings.SplitN(svc, ".", 3)
			svcName := ""
			proto := ""
			if len(parts) >= 2 {
				svcName = strings.TrimPrefix(parts[0], "_")
				proto = strings.TrimPrefix(parts[1], "_")
			}
			records = append(records, SRVRecord{
				Service:  svcName,
				Proto:    proto,
				Name:     svc + "." + domain,
				Target:   strings.TrimSuffix(addr.Target, "."),
				Port:     int(addr.Port),
				Priority: int(addr.Priority),
				Weight:   int(addr.Weight),
			})
		}
	}
	return records
}

func enumerateMX(domain string) []MXRecord {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := net.Resolver{}
	mxs, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return nil
	}
	var records []MXRecord
	for _, mx := range mxs {
		records = append(records, MXRecord{
			Host:       strings.TrimSuffix(mx.Host, "."),
			Preference: int(mx.Pref),
		})
	}
	return records
}

func queryCTLogs(domain string) []CTLogEntry {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json&limit=50", domain)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var entries []CTLogEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil
	}
	if len(entries) > 50 {
		entries = entries[:50]
	}
	return entries
}

func dnsCacheSnoop(domain string) []string {
	// Test common subdomains against public DNS resolvers
	// to detect cache entries (passive cache snooping)
	subdomains := []string{
		"www", "mail", "smtp", "imap", "pop3",
		"admin", "blog", "shop", "api", "cdn",
		"dev", "staging", "test", "vpn", "remote",
		"git", "svn", "jenkins", "jira", "confluence",
		"grafana", "prometheus", "kibana", "elastic",
		"ns1", "ns2", "mx1", "mx2",
		"autodiscover", "lyncdiscover", "msoid",
		"webmail", "owa", "exchange",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	var found []string
	for _, sub := range subdomains {
		fqdn := sub + "." + domain
		ips, err := resolver.LookupIPAddr(ctx, fqdn)
		if err == nil && len(ips) > 0 {
			found = append(found, fqdn)
		}
	}
	return found
}
