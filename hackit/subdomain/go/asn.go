package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// resolveASNs enriches results with ASN information
func resolveASNs(results []*Result, concurrency int) {
	sem := make(chan bool, concurrency)
	var wg sync.WaitGroup

	for _, r := range results {
		if len(r.IPs) == 0 {
			continue
		}
		wg.Add(1)
		sem <- true
		go func(res *Result) {
			defer wg.Done()
			defer func() { <-sem }()

			// Use the first IP for ASN lookup
			ip := res.IPs[0]

			// Try multiple resolvers
			for i := 0; i < 2; i++ {
				resolverAddr := publicResolvers[rand.Intn(len(publicResolvers))]
				resolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{Timeout: 2 * time.Second}
						return d.DialContext(ctx, "udp", resolverAddr)
					},
				}

				asn := lookupASN(resolver, ip)
				if asn != "" {
					res.ASN = asn
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}(r)
	}
	wg.Wait()
}

func lookupASN(resolver *net.Resolver, ip string) string {
	// Reverse IP
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	reversedIP := fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
	query := fmt.Sprintf("%s.origin.asn.cymru.com", reversedIP)

	txts, err := resolver.LookupTXT(context.Background(), query)
	if err != nil || len(txts) == 0 {
		return ""
	}

	// Format: "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
	// We just want "AS15169" or "AS15169 Google LLC"

	// Sometimes we might want more info, but let's stick to ASN number for now or the raw string
	// Let's parse it a bit
	fields := strings.Split(txts[0], "|")
	if len(fields) >= 1 {
		return "AS" + strings.TrimSpace(fields[0])
	}

	return strings.TrimSpace(txts[0])
}
