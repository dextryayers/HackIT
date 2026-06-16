package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type NetworkIntel struct {
	ASN      string `json:"asn"`
	Country  string `json:"country"`
	ISP      string `json:"isp"`
	Resolved string `json:"resolved"`
}

type IntelInfo struct {
	DNS     []string `json:"dns"`
	Reverse string   `json:"reverse"`
	WHOIS   string   `json:"whois"`
	Geo     string   `json:"geo"`
	ASN     string   `json:"asn"`
}

func GetNetworkIntel(host string) IntelInfo {
	intel := IntelInfo{
		DNS:     []string{},
		Reverse: "N/A",
		WHOIS:   "N/A",
		Geo:     "N/A",
		ASN:     "N/A",
	}

	// 1. Multi-Source DNS Resolution (Prefer IPv4)
	ips, err := net.LookupIP(host)
	if err == nil {
		// Add IPv4 first, then IPv6
		for _, ip := range ips {
			if ip.To4() != nil {
				intel.DNS = append(intel.DNS, ip.String())
			}
		}
		for _, ip := range ips {
			if ip.To4() == nil {
				intel.DNS = append(intel.DNS, ip.String())
			}
		}
	} else {
		// Fallback: system-level resolution using net.DefaultResolver
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err == nil {
			for _, addr := range ipAddrs {
				intel.DNS = append(intel.DNS, addr.IP.String())
			}
		}
	}
	
	// Ensure we have at least one entry if it's already an IP
	if len(intel.DNS) == 0 && net.ParseIP(host) != nil {
		intel.DNS = append(intel.DNS, host)
	}

	// 2. Reverse DNS
	if len(intel.DNS) > 0 {
		names, err := net.LookupAddr(intel.DNS[0])
		if err == nil && len(names) > 0 {
			intel.Reverse = strings.TrimSuffix(names[0], ".")
		}
	}

	// 3. WHOIS, GeoIP, ASN via Public APIs (Expert Mode)
	if len(intel.DNS) > 0 {
		ip := intel.DNS[0]

		// Use ip-api.com for GeoIP and ASN (Fast and No-Auth required for basic info)
		url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,zip,isp,org,as,query", ip)

		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			var data struct {
				Status     string `json:"status"`
				Country    string `json:"country"`
				RegionName string `json:"regionName"`
				City       string `json:"city"`
				Zip        string `json:"zip"`
				ISP        string `json:"isp"`
				Org        string `json:"org"`
				AS         string `json:"as"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Status == "success" {
				var parts []string
				if data.City != "" { parts = append(parts, data.City) }
				if data.RegionName != "" { parts = append(parts, data.RegionName) }
				if data.Country != "" { parts = append(parts, data.Country) }
				
				if len(parts) > 0 {
					intel.Geo = strings.Join(parts, ", ")
				}
				intel.ASN = data.AS
				intel.WHOIS = fmt.Sprintf("ISP: %s | ORG: %s", data.ISP, data.Org)
			}
		}
	}

	return intel
}
