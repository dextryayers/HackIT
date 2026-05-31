package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

func ParseWhois(domain string) *WhoisInfo {
	raw, err := queryWhois(domain)
	if err != nil {
		return &WhoisInfo{Registrar: "Lookup Failed", Org: "Unknown"}
	}

	info := &WhoisInfo{}
	
	// Pre-check for Privacy
	isRedacted := strings.Contains(strings.ToLower(raw), "privacy") || 
	              strings.Contains(strings.ToLower(raw), "redacted") || 
	              strings.Contains(strings.ToLower(raw), "protect") ||
	              strings.Contains(strings.ToLower(raw), "gdpr")
	              
	info.PrivacyEnabled = isRedacted

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, ">") { continue }
		
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 { continue }
		
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if val == "" { continue }
		
		switch {
		case key == "registrar":
			if info.Registrar == "" { info.Registrar = val }
		case strings.Contains(key, "iana id"):
			if info.IanaID == "" { info.IanaID = val }
		case key == "registrant organization" || key == "registrant org" || key == "org":
			if info.Org == "" { info.Org = val }
		case key == "registrant email" || key == "registrant contact email" || key == "email":
			if info.Email == "" { info.Email = val }
		case key == "admin email" || key == "admin contact email":
			if info.AdminEmail == "" { info.AdminEmail = val }
		case key == "tech email" || key == "tech contact email":
			if info.TechEmail == "" { info.TechEmail = val }
		case key == "creation date" || key == "created":
			if info.Created == "" { info.Created = val }
		case key == "registry expiry date" || key == "expiry date" || key == "expires":
			if info.Expires == "" { info.Expires = val }
		case key == "updated date" || key == "updated":
			if info.Updated == "" { info.Updated = val }
		case key == "registrant phone" || key == "phone":
			if info.Phone == "" { info.Phone = val }
		case strings.Contains(key, "abuse contact email"):
			if info.Abuse == "" { info.Abuse = val }
		case strings.Contains(key, "registrant street") || strings.Contains(key, "address"):
			info.Address += val + " "
		}
	}

	// Apply Privacy Overrides
	if isRedacted {
		if info.Org == "" || strings.Contains(strings.ToLower(info.Org), "redacted") { info.Org = "REDACTED FOR PRIVACY" }
		if info.Email == "" || strings.Contains(strings.ToLower(info.Email), "redacted") { info.Email = "REDACTED FOR PRIVACY" }
		if info.AdminEmail == "" || strings.Contains(strings.ToLower(info.AdminEmail), "redacted") { info.AdminEmail = "REDACTED FOR PRIVACY" }
		if info.TechEmail == "" || strings.Contains(strings.ToLower(info.TechEmail), "redacted") { info.TechEmail = "REDACTED FOR PRIVACY" }
		if info.Phone == "" || strings.Contains(strings.ToLower(info.Phone), "redacted") { info.Phone = "REDACTED FOR PRIVACY" }
	} else {
		// Fill empty with defaults to avoid visual blank spaces
		if info.Org == "" { info.Org = "Not Specified" }
		if info.Email == "" { info.Email = "Not Specified" }
		if info.AdminEmail == "" { info.AdminEmail = "Not Specified" }
		if info.TechEmail == "" { info.TechEmail = "Not Specified" }
		if info.Phone == "" { info.Phone = "Not Specified" }
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
