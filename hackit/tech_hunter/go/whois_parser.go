package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

// ParseWhois retrieves and parses raw WHOIS data for a domain
func ParseWhois(domain string) *WhoisInfo {
	raw, err := queryWhois(domain)
	if err != nil {
		return &WhoisInfo{Registrar: "Lookup Failed", Org: "Unknown"}
	}

	info := &WhoisInfo{}
	lines := strings.Split(raw, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" { continue }
		
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 { continue }
		
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		
		switch {
		case strings.Contains(key, "registrar"):
			if !strings.Contains(key, "url") && info.Registrar == "" { info.Registrar = val }
		case strings.Contains(key, "iana id"):
			info.IanaID = val
		case strings.Contains(key, "registrant organization") || strings.Contains(key, "org:"):
			info.Org = val
		case strings.Contains(key, "registrant email") || strings.Contains(key, "email:"):
			if info.Email == "" { info.Email = val }
		case strings.Contains(key, "creation date") || strings.Contains(key, "created:"):
			info.Created = val
		case strings.Contains(key, "expiry date") || strings.Contains(key, "expires:"):
			info.Expires = val
		case strings.Contains(key, "updated date") || strings.Contains(key, "updated:"):
			info.Updated = val
		case strings.Contains(key, "registrant phone") || strings.Contains(key, "phone:"):
			info.Phone = val
		case strings.Contains(key, "abuse"):
			if info.Abuse == "" { info.Abuse = val }
		case strings.Contains(key, "registrant street") || strings.Contains(key, "address:"):
			info.Address += val + " "
		}
	}

	if strings.Contains(strings.ToLower(raw), "privacy") || strings.Contains(strings.ToLower(raw), "redacted") {
		info.PrivacyEnabled = true
	}

	return info
}

func queryWhois(domain string) (string, error) {
	// Simple WHOIS query via port 43
	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", 5*time.Second)
	if err != nil { return "", err }
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)
	
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	ianaResult := string(buf[:n])

	// Find the specific WHOIS server for the TLD
	lines := strings.Split(ianaResult, "\n")
	whoisServer := ""
	for _, line := range lines {
		if strings.Contains(line, "whois:") {
			whoisServer = strings.TrimSpace(strings.Split(line, ":")[1])
			break
		}
	}

	if whoisServer == "" { return ianaResult, nil }

	// Query the actual TLD WHOIS server
	conn2, err := net.DialTimeout("tcp", whoisServer+":43", 5*time.Second)
	if err != nil { return ianaResult, nil }
	defer conn2.Close()

	fmt.Fprintf(conn2, "%s\r\n", domain)
	buf2, _ := ioutil.ReadAll(conn2)
	return string(buf2), nil
}
