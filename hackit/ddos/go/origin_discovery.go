package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type OriginDiscovery struct {
	Domain  string
	Origins []string
	CDNName string
	client  *http.Client
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func NewOriginDiscovery(domain string) *OriginDiscovery {
	return &OriginDiscovery{
		Domain: domain,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (o *OriginDiscovery) QueryCertLogs() []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", o.Domain)
	resp, err := o.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var results []string
	for _, e := range entries {
		names := strings.Split(e.NameValue, "\n")
		for _, n := range names {
			n = strings.TrimSpace(n)
			if n != "" && !seen[n] {
				seen[n] = true
				results = append(results, n)
			}
		}
	}
	return results
}

func (o *OriginDiscovery) QueryDNS() []string {
	ips, err := net.LookupIP(o.Domain)
	if err != nil {
		return nil
	}
	var out []string
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, ip4.String())
		}
	}
	return out
}

func (o *OriginDiscovery) DetectCDN() string {
	url := fmt.Sprintf("https://%s/", o.Domain)
	resp, err := o.client.Get(url)
	if err != nil {
		url = fmt.Sprintf("http://%s/", o.Domain)
		resp, err = o.client.Get(url)
		if err != nil {
			return ""
		}
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		switch k {
		case "Server":
			for _, val := range v {
				if strings.Contains(val, "cloudflare") || strings.Contains(val, "Cloudflare") {
					o.CDNName = "Cloudflare"
					return "Cloudflare"
				}
			}
		case "CF-Ray":
			o.CDNName = "Cloudflare"
			return "Cloudflare"
		case "X-Sucuri-ID":
			o.CDNName = "Sucuri"
			return "Sucuri"
		case "Akamai-Origin-Hop", "X-Akamai-Transformed":
			o.CDNName = "Akamai"
			return "Akamai"
		}
	}
	return ""
}

func (o *OriginDiscovery) FullDiscovery() []string {
	o.CDNName = o.DetectCDN()
	if o.CDNName != "" {
		fmt.Printf("  [ORIGIN] CDN detected: %s — searching for real origin IP\n", o.CDNName)
	}
	dnsIPs := o.QueryDNS()
	o.Origins = append(o.Origins, dnsIPs...)
	certNames := o.QueryCertLogs()
	for _, name := range certNames {
		if name == o.Domain || strings.Contains(name, "*") {
			continue
		}
		ips, _ := net.LookupIP(name)
		for _, ip := range ips {
			ipStr := ip.String()
			if ip4 := ip.To4(); ip4 != nil {
				ipStr = ip4.String()
			}
			dup := false
			for _, e := range o.Origins {
				if e == ipStr {
					dup = true
					break
				}
			}
			if !dup {
				o.Origins = append(o.Origins, ipStr)
			}
		}
	}
	return o.Origins
}
