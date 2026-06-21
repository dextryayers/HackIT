package dnsresolver

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Record struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

type Result struct {
	Host    string   `json:"host"`
	Records []Record `json:"records"`
}

type cacheEntry struct {
	records   []Record
	expiresAt time.Time
}

type Resolver struct {
	client *net.Resolver
	cache  sync.Map
	mu     sync.Mutex
}

func NewResolver() *Resolver {
	d := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 10 * time.Second,
	}
	return &Resolver{
		client: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return d.DialContext(ctx, network, address)
			},
		},
	}
}

func (r *Resolver) lookupWithCache(hostname, recordType string) []Record {
	cacheKey := hostname + ":" + recordType
	if val, ok := r.cache.Load(cacheKey); ok {
		entry := val.(cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.records
		}
		r.cache.Delete(cacheKey)
	}
	return nil
}

func (r *Resolver) setCache(hostname, recordType string, records []Record, ttl uint32) {
	cacheKey := hostname + ":" + recordType
	var maxTTL uint32 = 60
	if ttl > 0 {
		maxTTL = ttl
	}
	r.cache.Store(cacheKey, cacheEntry{
		records:   records,
		expiresAt: time.Now().Add(time.Duration(maxTTL) * time.Second),
	})
}

func (r *Resolver) lookupA(ctx context.Context, hostname string) []Record {
	if cached := r.lookupWithCache(hostname, "A"); cached != nil {
		return cached
	}
	ips, err := r.client.LookupHost(ctx, hostname)
	if err != nil {
		return nil
	}
	var records []Record
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			continue
		}
		records = append(records, Record{Type: "A", Value: ip, TTL: 3600})
	}
	if len(records) > 0 {
		r.setCache(hostname, "A", records, 3600)
	}
	return records
}

func (r *Resolver) lookupAAAA(ctx context.Context, hostname string) []Record {
	if cached := r.lookupWithCache(hostname, "AAAA"); cached != nil {
		return cached
	}
	ips, err := r.client.LookupHost(ctx, hostname)
	if err != nil {
		return nil
	}
	var records []Record
	for _, ip := range ips {
		if !strings.Contains(ip, ":") {
			continue
		}
		records = append(records, Record{Type: "AAAA", Value: ip, TTL: 3600})
	}
	if len(records) > 0 {
		r.setCache(hostname, "AAAA", records, 3600)
	}
	return records
}

func (r *Resolver) lookupMX(ctx context.Context, hostname string) []Record {
	if cached := r.lookupWithCache(hostname, "MX"); cached != nil {
		return cached
	}
	mxs, err := r.client.LookupMX(ctx, hostname)
	if err != nil {
		return nil
	}
	var records []Record
	for _, mx := range mxs {
		records = append(records, Record{
			Type: "MX", Value: fmt.Sprintf("%d %s", mx.Pref, mx.Host), TTL: 3600,
		})
	}
	if len(records) > 0 {
		r.setCache(hostname, "MX", records, 3600)
	}
	return records
}

func (r *Resolver) lookupTXT(ctx context.Context, hostname string) []Record {
	if cached := r.lookupWithCache(hostname, "TXT"); cached != nil {
		return cached
	}
	txts, err := r.client.LookupTXT(ctx, hostname)
	if err != nil {
		return nil
	}
	var records []Record
	for _, txt := range txts {
		if len(txt) > 200 {
			txt = txt[:200]
		}
		records = append(records, Record{Type: "TXT", Value: txt, TTL: 3600})
	}
	if len(records) > 0 {
		r.setCache(hostname, "TXT", records, 3600)
	}
	return records
}

func (r *Resolver) lookupNS(ctx context.Context, hostname string) []Record {
	if cached := r.lookupWithCache(hostname, "NS"); cached != nil {
		return cached
	}
	nss, err := r.client.LookupNS(ctx, hostname)
	if err != nil {
		return nil
	}
	var records []Record
	for _, ns := range nss {
		records = append(records, Record{Type: "NS", Value: ns.Host, TTL: 3600})
	}
	if len(records) > 0 {
		r.setCache(hostname, "NS", records, 3600)
	}
	return records
}

func (r *Resolver) lookupCNAME(ctx context.Context, hostname string) []Record {
	if cached := r.lookupWithCache(hostname, "CNAME"); cached != nil {
		return cached
	}
	cname, err := r.client.LookupCNAME(ctx, hostname)
	if err != nil || cname == "" {
		return nil
	}
	records := []Record{{Type: "CNAME", Value: cname, TTL: 3600}}
	r.setCache(hostname, "CNAME", records, 3600)
	return records
}

func (r *Resolver) lookupSOA(ctx context.Context, hostname string) []Record {
	if cached := r.lookupWithCache(hostname, "SOA"); cached != nil {
		return cached
	}
	ns, err := r.client.LookupNS(ctx, hostname)
	if err != nil || len(ns) == 0 {
		return nil
	}
	records := []Record{{Type: "SOA", Value: ns[0].Host + " admin", TTL: 3600}}
	r.setCache(hostname, "SOA", records, 3600)
	return records
}

func main() {
	target := flag.String("target", "", "Hostname to resolve")
	recordType := flag.String("type", "A", "Record type (A, AAAA, MX, TXT, NS, CNAME, SOA)")
	flag.Parse()

	if *target == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -target <hostname> -type <record_type>\n", os.Args[0])
		os.Exit(1)
	}

	validTypes := map[string]bool{"A": true, "AAAA": true, "MX": true, "TXT": true, "NS": true, "CNAME": true, "SOA": true}
	if !validTypes[strings.ToUpper(*recordType)] {
		fmt.Fprintf(os.Stderr, "Invalid record type: %s\n", *recordType)
		os.Exit(1)
	}

	resolver := NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rt := strings.ToUpper(*recordType)

	var records []Record
	var mu sync.Mutex
	var wg sync.WaitGroup

	lookups := map[string]func(context.Context, string) []Record{
		"A":     resolver.lookupA,
		"AAAA":  resolver.lookupAAAA,
		"MX":    resolver.lookupMX,
		"TXT":   resolver.lookupTXT,
		"NS":    resolver.lookupNS,
		"CNAME": resolver.lookupCNAME,
		"SOA":   resolver.lookupSOA,
	}

	if rt == "ALL" {
		for rtName, lookupFn := range lookups {
			wg.Add(1)
			go func(name string, fn func(context.Context, string) []Record) {
				defer wg.Done()
				recs := fn(ctx, *target)
				mu.Lock()
				records = append(records, recs...)
				mu.Unlock()
			}(rtName, lookupFn)
		}
	} else {
		if fn, ok := lookups[rt]; ok {
			records = fn(ctx, *target)
		}
	}

	wg.Wait()

	if records == nil {
		records = []Record{}
	}

	result := Result{Host: *target, Records: records}
	data, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
