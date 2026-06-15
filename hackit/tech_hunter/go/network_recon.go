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

type NetworkInfo struct {
	IP           string   `json:"ip"`
	IPRange      string   `json:"ip_range"`
	PublicIPs    []string `json:"public_ips"`
	ASN          string   `json:"asn"`
	ASNRoute     string   `json:"asn_route"`
	ASNCountry   string   `json:"asn_country"`
	Hosting      string   `json:"hosting"`
	ReverseDNS   string   `json:"reverse_dns"`
	Geo          string   `json:"geo"`
	GeoCity      string   `json:"geo_city"`
	GeoRegion    string   `json:"geo_region"`
	GeoCountry   string   `json:"geo_country"`
	GeoLat       float64  `json:"geo_lat"`
	GeoLon       float64  `json:"geo_lon"`
	NetOwner     string   `json:"net_owner"`
	ISP          string   `json:"isp"`
	AbuseContact string   `json:"abuse_contact"`
	Proxy        bool     `json:"proxy"`
	Mobile       bool     `json:"mobile"`
	Notes        string   `json:"notes"`
	OS           string   `json:"os"`
}

type ipAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	ASName      string  `json:"asname"`
	Reverse     string  `json:"reverse"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
	Message     string  `json:"message"`
}

func PerformNetworkRecon(ips []string) []*NetworkInfo {
	results := []*NetworkInfo{}

	for _, ip := range ips {
		info := &NetworkInfo{
			IP:        ip,
			PublicIPs: []string{ip},
		}

		ptrs := lookupAddrTimeout(ip)
		if len(ptrs) > 0 {
			info.ReverseDNS = ptrs[0]
		}

		queryIPInfo(ip, info)

		if info.ASN != "" {
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				info.IPRange = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
			}
		}

		results = append(results, info)
	}

	return results
}

func queryIPInfo(ip string, info *NetworkInfo) {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting", ip)

	resp, err := client.Get(url)
	if err != nil {
		info.Geo = "Lookup failed"
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data ipAPIResponse
	if err := json.Unmarshal(body, &data); err != nil {
		info.Geo = "Parse failed"
		return
	}

	if data.Status != "success" {
		info.Geo = fmt.Sprintf("Error: %s", data.Message)
		return
	}

	info.Geo = fmt.Sprintf("%s, %s, %s", data.City, data.Region, data.Country)
	info.GeoCity = data.City
	info.GeoRegion = data.Region
	info.GeoCountry = data.Country
	info.GeoLat = data.Lat
	info.GeoLon = data.Lon
	info.ISP = data.ISP

	info.ASN = data.AS
	info.ASNRoute = data.ASName
	info.ASNCountry = data.CountryCode
	info.NetOwner = data.Org

	if data.Hosting {
		info.Hosting = "Cloud/Hosting Provider"
	} else {
		info.Hosting = "Residential/Corporate"
	}

	info.Proxy = data.Proxy
	info.Mobile = data.Mobile

	notes := []string{}
	if data.ISP != "" {
		notes = append(notes, fmt.Sprintf("ISP: %s", data.ISP))
	}
	if data.Proxy {
		notes = append(notes, "Proxy/VPN detected")
	}
	if data.Mobile {
		notes = append(notes, "Mobile network")
	}
	info.Notes = strings.Join(notes, ", ")
}

func lookupAddrTimeout(ip string) []string {
	ch := make(chan []string, 1)
	go func() {
		ptrs, _ := net.LookupAddr(ip)
		ch <- ptrs
	}()
	select {
	case ptrs := <-ch:
		return ptrs
	case <-time.After(3 * time.Second):
		return nil
	}
}
