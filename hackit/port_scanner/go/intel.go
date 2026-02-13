package main

import (
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

	// 1. DNS Lookup
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			intel.DNS = append(intel.DNS, ip.String())
		}
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
				intel.Geo = fmt.Sprintf("%s, %s, %s", data.City, data.RegionName, data.Country)
				intel.ASN = data.AS
				intel.WHOIS = fmt.Sprintf("ISP: %s | ORG: %s", data.ISP, data.Org)
			}
		}
	}

	return intel
}
