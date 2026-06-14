package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Resolver struct {
	Address   string
	Client    *net.Resolver
	mu        sync.Mutex
}

func NewResolver(address string) *Resolver {
	if address == "" {
		return &Resolver{Client: net.DefaultResolver}
	}
	return &Resolver{
		Address: address,
		Client: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", address)
			},
		},
	}
}

func LoadResolvers(path string) []string {
	if path == "" { return nil }
	f, err := os.Open(path)
	if err != nil { return nil }
	defer f.Close()
	var resolvers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			resolvers = append(resolvers, line)
		}
	}
	return resolvers
}

func (r *Resolver) LookupHost(host string) ([]string, error) {
	return r.Client.LookupHost(nil, host)
}

func (r *Resolver) LookupCNAME(host string) (string, error) {
	return r.Client.LookupCNAME(nil, host)
}

func ScanAllIPs(host string, resolvers []string) []string {
	ips := make(map[string]bool)
	for _, addr := range resolvers {
		res := NewResolver(addr)
		addrs, err := res.LookupHost(host)
		if err == nil {
			for _, ip := range addrs {
				ips[ip] = true
			}
		}
	}
	// also use system resolver
	addrs, err := net.LookupHost(host)
	if err == nil {
		for _, ip := range addrs {
			ips[ip] = true
		}
	}
	result := make([]string, 0, len(ips))
	for ip := range ips {
		result = append(result, ip)
	}
	return result
}

func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil { return nil, err }
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 { break }
	}
}

func ResolveTargets(targets []string, scanAll bool, resolvers []string) []string {
	results := make(map[string]bool)
	for _, t := range targets {
		parsed := ParseTarget(t)
		results[parsed.URL] = true
		if scanAll {
			ips := ScanAllIPs(parsed.Host, resolvers)
			for _, ip := range ips {
				u := fmt.Sprintf("%s://%s:%s%s", parsed.Scheme, ip, parsed.Port, parsed.Path)
				results[u] = true
			}
		}
	}
	out := make([]string, 0, len(results))
	for u := range results { out = append(out, u) }
	return out
}
