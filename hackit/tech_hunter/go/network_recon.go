package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

type NetworkInfo struct {
	IPRange      string `json:"ip_range"`
	PublicIPs    []string `json:"public_ips"`
	ASN          string `json:"asn"`
	ASNRoute     string `json:"asn_route"`
	Hosting      string `json:"hosting"`
	ReverseDNS   string `json:"reverse_dns"`
	Geo          string `json:"geo"`
	NetOwner     string `json:"net_owner"`
	AbuseContact string `json:"abuse_contact"`
	Notes        string `json:"notes"`
	OS           string `json:"os"`
}

func PerformNetworkRecon(ips []string) []*NetworkInfo {
	results := []*NetworkInfo{}
	
	for _, ip := range ips {
		info := &NetworkInfo{
			PublicIPs: []string{ip},
		}

		// 1. Reverse DNS (PTR)
		ptrs, _ := net.LookupAddr(ip)
		if len(ptrs) > 0 {
			info.ReverseDNS = ptrs[0]
		}

		// 2. IP Geo & ASN
		queryIPInfo(ip, info)
		
		// 3. CIDR Discovery (using heuristic)
		if info.ASN != "" {
			info.IPRange = fmt.Sprintf("%s/24 (Derived from ISP)", ip) // Simple heuristic
		}
		
		results = append(results, info)
	}

	return results
}

func queryIPInfo(ip string, info *NetworkInfo) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,regionName,city,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting", ip)
	
	resp, err := client.Get(url)
	if err != nil { return }
	defer resp.Body.Close()

	var data map[string]interface{}
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &data)

	if data["status"] == "success" {
		info.Geo = fmt.Sprintf("%s, %s, %s (Lat: %v, Lon: %v)", 
			data["city"], data["regionName"], data["country"], data["lat"], data["lon"])
		info.ASN = fmt.Sprintf("%v", data["as"])
		info.NetOwner = fmt.Sprintf("%v", data["org"])
		info.ASNRoute = fmt.Sprintf("%v", data["asname"])
		
		if data["hosting"] == true {
			info.Hosting = "Cloud/Hosting Provider"
		} else {
			info.Hosting = "Residential/Corporate"
		}

		info.Notes = fmt.Sprintf("ISP: %v, Proxy: %v", data["isp"], data["proxy"])
	} else {
		info.Geo = "Data Unavailable"
		info.ASN = "Lookup Failed"
		info.Hosting = "Unknown"
	}
}
