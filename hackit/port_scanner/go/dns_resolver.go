package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type dnsCacheRecord struct {
	ips    []string
	expiry time.Time
}

var (
	dnsResolverCache sync.Map
	dnsResolverPool  = sync.Pool{
		New: func() interface{} { return &net.Resolver{} },
	}
)

func getResolver() *net.Resolver {
	return net.DefaultResolver
}

func ResolveHost(host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}
	}

	val, ok := dnsResolverCache.Load(host)
	if ok {
		rec := val.(*dnsCacheRecord)
		if time.Now().Before(rec.expiry) {
			return rec.ips
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := getResolver().LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil
	}

	clean := make([]string, 0, len(ips))
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			clean = append(clean, ip)
		}
	}

	dnsResolverCache.Store(host, &dnsCacheRecord{
		ips:    clean,
		expiry: time.Now().Add(5 * time.Minute),
	})
	return clean
}

func ReverseLookup(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	names, err := getResolver().LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimRight(names[0], ".")
}

func ResolveMX(domain string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := getResolver().LookupMX(ctx, domain)
	if err != nil || len(records) == 0 {
		return nil
	}

	out := make([]string, 0, len(records))
	for _, mx := range records {
		out = append(out, fmt.Sprintf("%s %d", strings.TrimRight(mx.Host, "."), mx.Pref))
	}
	return out
}

func ResolveNS(domain string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := getResolver().LookupNS(ctx, domain)
	if err != nil || len(records) == 0 {
		return nil
	}

	out := make([]string, 0, len(records))
	for _, ns := range records {
		out = append(out, strings.TrimRight(ns.Host, "."))
	}
	return out
}

func ResolveSRV(service, proto, name string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, addrs, err := getResolver().LookupSRV(ctx, service, proto, name)
	if err != nil || len(addrs) == 0 {
		return nil
	}

	out := make([]string, 0, len(addrs))
	for _, srv := range addrs {
		out = append(out, fmt.Sprintf("%s:%d priority=%d weight=%d",
			strings.TrimRight(srv.Target, "."), srv.Port, srv.Priority, srv.Weight))
	}
	return out
}
