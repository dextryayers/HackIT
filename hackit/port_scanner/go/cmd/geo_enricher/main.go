package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type GeoResult struct {
	IP      string  `json:"ip"`
	Country string  `json:"country"`
	City    string  `json:"city"`
	Org     string  `json:"org"`
	ASN     string  `json:"asn"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

type ipAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Query       string  `json:"query"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	Zip         string  `json:"zip"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Message     string  `json:"message"`
}

type geoCacheEntry struct {
	result    GeoResult
	expiresAt time.Time
}

type GeoEnricher struct {
	client *http.Client
	cache  sync.Map
}

func NewGeoEnricher() *GeoEnricher {
	return &GeoEnricher{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  false,
				DisableKeepAlives:   false,
			},
		},
	}
}

func (g *GeoEnricher) getFromCache(ip string) *GeoResult {
	if val, ok := g.cache.Load(ip); ok {
		entry := val.(geoCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return &entry.result
		}
		g.cache.Delete(ip)
	}
	return nil
}

func (g *GeoEnricher) setCache(ip string, result GeoResult) {
	g.cache.Store(ip, geoCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(24 * time.Hour),
	})
}

func (g *GeoEnricher) lookupIPAPI(ip string) (*GeoResult, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,org,as,lat,lon,query,message", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}
	req.Header.Set("User-Agent", "HackIT-Port-Scanner/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("response read failed: %w", err)
	}

	var apiResp ipAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("JSON parse failed: %w", err)
	}

	if apiResp.Status == "fail" {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	result := GeoResult{
		IP:      apiResp.Query,
		Country: apiResp.Country,
		City:    apiResp.City,
		Org:     apiResp.Org,
		ASN:     apiResp.AS,
		Lat:     apiResp.Lat,
		Lon:     apiResp.Lon,
	}

	return &result, nil
}

func (g *GeoEnricher) enrich(ip string) (*GeoResult, error) {
	if cached := g.getFromCache(ip); cached != nil {
		return cached, nil
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	if parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast() || parsedIP.IsUnspecified() {
		result := GeoResult{
			IP:      ip,
			Country: "Private",
			City:    "Private",
			Org:     "Private Network",
			ASN:     "N/A",
			Lat:     0,
			Lon:     0,
		}
		g.setCache(ip, result)
		return &result, nil
	}

	result, err := g.lookupIPAPI(ip)
	if err != nil {
		return nil, err
	}

	g.setCache(ip, *result)
	return result, nil
}

func main() {
	ip := flag.String("ip", "", "IP address to lookup")
	flag.Parse()

	if *ip == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -ip <ip_address>\n", os.Args[0])
		os.Exit(1)
	}

	enricher := NewGeoEnricher()
	result, err := enricher.enrich(*ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Geo enrichment failed: %v\n", err)
		result = &GeoResult{
			IP:      *ip,
			Country: "Unknown",
			City:    "Unknown",
			Org:     "Unknown",
			ASN:     "Unknown",
		}
	}

	data, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
