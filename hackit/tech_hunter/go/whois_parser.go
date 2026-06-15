package main

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func ParseWhois(domain string) *WhoisInfo {
	raw, err := queryWhois(domain)
	if err != nil {
		return &WhoisInfo{Registrar: "Lookup Failed", Org: "Unknown", PrivacyEnabled: false}
	}

	info := &WhoisInfo{}
	rawLower := strings.ToLower(raw)

	isRedacted := strings.Contains(rawLower, "privacy") ||
		strings.Contains(rawLower, "redacted") ||
		strings.Contains(rawLower, "protect") ||
		strings.Contains(rawLower, "gdpr") ||
		strings.Contains(rawLower, "data.redacted") ||
		strings.Contains(rawLower, "whoisguard") ||
		strings.Contains(rawLower, "whoguard") ||
		strings.Contains(rawLower, "privacyprotect")

	info.PrivacyEnabled = isRedacted

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, ">") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if val == "" || val == "NOT DISCLOSED" || val == "REDACTED" {
			continue
		}

		switch {
		case key == "registrar":
			if info.Registrar == "" {
				info.Registrar = val
			}
		case strings.Contains(key, "iana id") || key == "registration service provider":
			if info.IanaID == "" {
				info.IanaID = val
			}
		case key == "registrant organization" || key == "registrant org" || key == "org" || key == "organisation":
			if info.Org == "" {
				info.Org = val
			}
		case key == "registrant email" || key == "registrant contact email" || key == "email":
			if info.Email == "" {
				info.Email = val
			}
		case key == "admin email" || key == "admin contact email":
			if info.AdminEmail == "" {
				info.AdminEmail = val
			}
		case key == "tech email" || key == "tech contact email":
			if info.TechEmail == "" {
				info.TechEmail = val
			}
		case key == "creation date" || key == "created" || key == "domain registration date":
			if info.Created == "" {
				info.Created = val
			}
		case key == "registry expiry date" || key == "expiry date" || key == "expires" || key == "registrar registration expiration date":
			if info.Expires == "" {
				info.Expires = val
			}
		case key == "updated date" || key == "updated" || key == "last updated":
			if info.Updated == "" {
				info.Updated = val
			}
		case key == "registrant phone" || key == "phone" || key == "registrant telephone":
			if info.Phone == "" {
				info.Phone = val
			}
		case strings.Contains(key, "abuse contact email") || key == "abuse email":
			if info.Abuse == "" {
				info.Abuse = val
			}
		case strings.Contains(key, "registrant street") || strings.Contains(key, "registrant address"):
			if info.Address != "" { info.Address += ", " }
			info.Address += val
		case key == "registrant city":
			if info.Address != "" { info.Address += ", " }
			info.Address += val
		case key == "registrant state" || key == "registrant province":
			if info.Address != "" { info.Address += ", " }
			info.Address += val
		case key == "registrant postal code" || key == "registrant zip":
			info.Address += " " + val
		case key == "registrant country" || key == "country":
			info.Address += ", " + val
		case key == "name server" || key == "nserver":
			info.NameServers = append(info.NameServers, val)
		case key == "dnssec":
			info.DNSSEC = val
		case key == "registrant name" || key == "registrant contact name":
			if info.RegistrantName == "" { info.RegistrantName = val }
		case key == "registrant id" || key == "registrant contact id":
			if info.RegistrantID == "" { info.RegistrantID = val }
		case strings.Contains(key, "referral url") || key == "whois server":
			if info.WhoisServer == "" { info.WhoisServer = val }
		case key == "status":
			info.DomainStatuses = append(info.DomainStatuses, val)
		case key == "admin organization" || key == "admin org":
			if info.AdminOrg == "" { info.AdminOrg = val }
		case key == "admin phone":
			if info.AdminPhone == "" { info.AdminPhone = val }
		case key == "tech organization" || key == "tech org":
			if info.TechOrg == "" { info.TechOrg = val }
		case key == "tech phone":
			if info.TechPhone == "" { info.TechPhone = val }
		}
	}

	info.Address = strings.TrimSpace(info.Address)
	info.Address = strings.TrimPrefix(info.Address, ",")
	info.Address = strings.TrimSpace(info.Address)
	if info.NameServers == nil {
		info.NameServers = []string{}
	}
	if info.DomainStatuses == nil {
		info.DomainStatuses = []string{}
	}

	if isRedacted {
		if info.Org == "" || strings.Contains(strings.ToLower(info.Org), "redacted") {
			info.Org = "REDACTED FOR PRIVACY"
		}
		if info.Email == "" || strings.Contains(strings.ToLower(info.Email), "redacted") {
			info.Email = "REDACTED FOR PRIVACY"
		}
		if info.AdminEmail == "" || strings.Contains(strings.ToLower(info.AdminEmail), "redacted") {
			info.AdminEmail = "REDACTED FOR PRIVACY"
		}
		if info.TechEmail == "" || strings.Contains(strings.ToLower(info.TechEmail), "redacted") {
			info.TechEmail = "REDACTED FOR PRIVACY"
		}
		if info.Phone == "" || strings.Contains(strings.ToLower(info.Phone), "redacted") {
			info.Phone = "REDACTED FOR PRIVACY"
		}
	} else {
		if info.Org == "" {
			info.Org = "Not Specified"
		}
		if info.Email == "" {
			info.Email = "Not Specified"
		}
		if info.AdminEmail == "" {
			info.AdminEmail = "Not Specified"
		}
		if info.TechEmail == "" {
			info.TechEmail = "Not Specified"
		}
		if info.Phone == "" {
			info.Phone = "Not Specified"
		}
	}

	return info
}

func queryWhois(domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", 2*time.Second)
	if err != nil {
		return queryWhoisDirect(domain)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	ianaResult := string(buf[:n])

	whoisServer := ""
	for _, line := range strings.Split(ianaResult, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "whois:") {
			whoisServer = strings.TrimSpace(trimmed[6:])
			break
		}
		if strings.Contains(strings.ToLower(trimmed), "refer:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				whoisServer = strings.TrimSpace(parts[1])
			}
		}
	}

	if whoisServer == "" {
		return ianaResult, nil
	}

	return queryWhoisServer(whoisServer, domain)
}

func queryWhoisDirect(domain string) (string, error) {
	// Fallback direct to common WHOIS server
	return queryWhoisServer("whois.verisign-grs.com", domain)
}

func queryWhoisServer(server, domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("whois lookup failed for %s: %v", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(4 * time.Second))
	fmt.Fprintf(conn, "%s\r\n", domain)
	body, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("whois read failed: %v", err)
	}
	return string(body), nil
}
