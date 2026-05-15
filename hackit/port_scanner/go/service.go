package main

import (
	"fmt"
	"regexp"
	"strings"
)

// commonPorts is now globally defined in ports.go to ensure synchronization across engines.

func DetectService(port int, banner string, host string) (string, string) {
	// 0. Try Rust fingerprinting (High Power)
	rustService := RustFingerprintService(banner)
	version := RustExtractVersion(banner, rustService)

	if strings.ToUpper(rustService) != "UNKNOWN" {
		return rustService, version
	}

	// 1. Check Banner Content (High Confidence)
	bannerRaw := banner
	bannerLower := strings.ToLower(banner)
	isSSL := strings.Contains(bannerLower, "[ssl]")
	bannerLower = strings.ReplaceAll(bannerLower, "[ssl]: ", "")

	// Explicit Mapping for Industrial SSL Ports (Surgical Accuracy)
	if isSSL {
		switch port {
		case 465: return "SMTPS (SMTP over SSL / submissions)", ExtractSMTPVersion(bannerRaw)
		case 993: return "IMAPS (IMAP over SSL)", ExtractIMAPVersion(bannerRaw)
		case 995: return "POP3S (POP3 over SSL)", ExtractPOP3Version(bannerRaw)
		case 2083: return "cPanel (SSL)", "cPanel/WHM Managed SSL"
		case 2087: return "cPanel WHM (SSL)", "cPanel/WHM Admin SSL"
		}
	}

	// LAST RESORT: Forced mapping for quiet but common ports
	if bannerRaw == "" || strings.ToUpper(rustService) == "UNKNOWN" {
		switch port {
		case 2082: return "cPanel (HTTP)", "cPanel/WHM Managed"
		case 2086: return "cPanel WHM (HTTP)", "cPanel/WHM Admin"
		case 8081: return "HTTP Alternate / Proxy", "N/A"
		}
	}

	// SSH detection - check banner content first
	if strings.Contains(bannerLower, "ssh") || strings.Contains(bannerLower, "ssh-") {
		version = ExtractSSHVersion(banner)
		// Get proper service name
		if strings.Contains(bannerLower, "openssh") {
			return "openssh", version
		}
		return "ssh", version
	}

	// FTP detection - check banner content first
	if strings.Contains(bannerLower, "ftp") || strings.Contains(bannerLower, "220 ") {
		version = ExtractFTPVersion(banner)
		// Check for specific FTP server
		if strings.Contains(bannerLower, "proftpd") {
			return "proftpd", version
		}
		if strings.Contains(bannerLower, "vsftpd") {
			return "vsftpd", version
		}
		if strings.Contains(bannerLower, "filezilla") {
			return "filezilla", version
		}
		if strings.Contains(bannerLower, "pure-ftpd") {
			return "pure-ftpd", version
		}
		return "ftp", version
	}

	// SMTP detection
	if strings.Contains(bannerLower, "smtp") || strings.Contains(bannerLower, "esmtp") || strings.Contains(bannerLower, "postfix") || strings.Contains(bannerLower, "sendmail") {
		version = ExtractSMTPVersion(banner)
		// Check for specific SMTP server
		if strings.Contains(bannerLower, "postfix") {
			return "postfix", version
		}
		if strings.Contains(bannerLower, "exim") {
			return "exim", version
		}
		if strings.Contains(bannerLower, "sendmail") {
			return "sendmail", version
		}
		return "smtp", version
	}

	// HTTP detection
	if strings.Contains(bannerLower, "http") || strings.Contains(bannerLower, "html") || strings.Contains(bannerLower, "server:") {
		version = ExtractHTTPVersion(banner)
		return "http", version
	}

	// Database detection
	if strings.Contains(bannerLower, "mysql") {
		version = ExtractMySQLVersion(banner)
		return "mysql", version
	}
	if strings.Contains(bannerLower, "postgresql") {
		version = ExtractPostgreSQLVersion(banner)
		return "postgresql", version
	}
	if strings.Contains(bannerLower, "mssql") || strings.Contains(bannerLower, "sql server") {
		version = ExtractMSSQLVersion(banner)
		return "mssql", version
	}
	if strings.Contains(bannerLower, "oracle") {
		version = ExtractOracleVersion(banner)
		return "oracle", version
	}
	if strings.Contains(bannerLower, "redis") {
		version = ExtractRedisVersion(banner)
		return "redis", version
	}
	if strings.Contains(bannerLower, "mongodb") {
		version = ExtractMongoDBVersion(banner)
		return "mongodb", version
	}

	// Email protocols
	if strings.Contains(bannerLower, "pop3") || strings.Contains(bannerLower, "pop3d") {
		version = ExtractPOP3Version(banner)
		return "pop3", version
	}
	if strings.Contains(bannerLower, "imap") || strings.Contains(bannerLower, "imapd") {
		version = ExtractIMAPVersion(banner)
		return "imap", version
	}

	// Telnet
	if strings.Contains(bannerLower, "telnet") {
		version = ExtractTelnetVersion(banner)
		return "telnet", version
	}

	// VNC
	if strings.Contains(bannerLower, "rfb") || strings.Contains(bannerLower, "vnc") {
		version = ExtractVNCVersion(banner)
		return "vnc", version
	}

	// RDP
	if strings.Contains(bannerLower, "mstsc") || strings.Contains(bannerLower, "rdp") {
		version = ExtractRDPVersion(banner)
		return "rdp", version
	}

	// Specific Web Servers (LiteSpeed, etc.)
	if strings.Contains(bannerLower, "litespeed") {
		return "litespeed", ExtractHTTPVersion(banner)
	}
	if strings.Contains(bannerLower, "openresty") {
		return "openresty", ExtractHTTPVersion(banner)
	}
	if strings.Contains(bannerLower, "cloudflare") {
		return "cloudflare", "Cloudflare"
	}
	if strings.Contains(bannerLower, "caddy") {
		return "caddy", ExtractHTTPVersion(banner)
	}
	if strings.Contains(bannerLower, "gws") {
		return "gws", "Google Web Server"
	}

	// Control Panels
	if strings.Contains(bannerLower, "cpanel") {
		return "cpanel", "cPanel/WHM"
	}
	if strings.Contains(bannerLower, "plesk") {
		return "plesk", "Plesk"
	}

	// 2. Fallback to Common Ports (Medium Confidence)
	if name, ok := commonPorts[port]; ok {
		// Even if banner is unknown, we can guess the service by port
		return name, version
	}

	if name := GetIANAService(port); name != "" {
		return name, version
	}

	return fmt.Sprintf("unassigned/%d", port), version
}

// IdentifyService is an alias for DetectService for backward compatibility
func IdentifyService(port int, banner string, host string) (string, string) {
	return DetectService(port, banner, host)
}

// ExtractSSHVersion extracts SSH version from banner
func ExtractSSHVersion(banner string) string {
	// Format: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
	re := regexp.MustCompile(`SSH-([\d.]+)-([\w._-]+)[\s/]*([\w._-]+)?`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 2 {
		ver := matches[2]
		if len(matches) > 3 && matches[3] != "" {
			ver += " (" + matches[3] + ")"
		}
		return ver
	}
	return "Standard SSH"
}

// ExtractFTPVersion extracts FTP version from banner
func ExtractFTPVersion(banner string) string {
	bannerLower := strings.ToLower(banner)

	// Try various FTP server formats
	// Pure-FTPd: "220---------- Welcome to Pure-FTPd [privsep] ..."
	if strings.Contains(bannerLower, "pure-ftpd") {
		re := regexp.MustCompile(`[Pp]ure-[Ff][Tt][Pp]d[\s\[]*([\d.]+)?`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "Pure-FTPd " + matches[1]
		}
		return "Pure-FTPd"
	}

	// ProFTPD: "220 ProFTPD 1.3.5 Server"
	if strings.Contains(bannerLower, "proftpd") {
		re := regexp.MustCompile(`[Pp]ro[Ff][Tt][Pp][Dd][\s/]*([\d.]+)?`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "ProFTPD " + matches[1]
		}
		return "ProFTPD"
	}

	// vsftpd: "220 (vsFTPd 3.0.3)"
	if strings.Contains(bannerLower, "vsftpd") {
		re := regexp.MustCompile(`[Vv][Ss][Ff][Tt][Pp][Dd][\s/]*([\d.]+)?`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "vsftpd " + matches[1]
		}
		return "vsftpd"
	}

	// FileZilla: "220-FileZilla Server 1.5.1"
	if strings.Contains(bannerLower, "filezilla") {
		re := regexp.MustCompile(`[Ff]ile[Zz]illa[\s\-]*[Ss]erver?[\s/]*([\d.]+)?`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "FileZilla " + matches[1]
		}
		return "FileZilla"
	}

	// Generic: "220 ServerName 1.2.3"
	re := regexp.MustCompile(`220[\s\-]+([A-Za-z][A-Za-z0-9\-_]+)[\s/]*([\d.]+)?`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		if len(matches) > 2 && matches[2] != "" {
			return matches[1] + " " + matches[2]
		}
		return matches[1]
	}

	return ""
}

// ExtractSMTPVersion extracts SMTP version from banner
func ExtractSMTPVersion(banner string) string {
	bannerLower := strings.ToLower(banner)

	// Postfix: "220 mail.example.com ESMTP Postfix 3.4.13"
	if strings.Contains(bannerLower, "postfix") {
		re := regexp.MustCompile(`[Pp]ostfix[^0-9]*([0-9._-]+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "Postfix " + matches[1]
		}
		return "Postfix"
	}

	// Exim: "220 mail.example.com ESMTP Exim 4.95"
	if strings.Contains(bannerLower, "exim") {
		re := regexp.MustCompile(`[Ee]xim[^0-9]*([0-9._-]+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "Exim " + matches[1]
		}
		return "Exim"
	}

	// Sendmail: "220 mail.example.com ESMTP Sendmail 8.17.1"
	if strings.Contains(bannerLower, "sendmail") {
		re := regexp.MustCompile(`[Ss]endmail[^0-9]*([0-9._-]+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "Sendmail " + matches[1]
		}
		return "Sendmail"
	}

	// Dovecot: "220 mail.example.com ESMTP Dovecot"
	if strings.Contains(bannerLower, "dovecot") {
		re := regexp.MustCompile(`[Dd]ovecot[^0-9]*([0-9._-]+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "Dovecot " + matches[1]
		}
		return "Dovecot"
	}

	// Courier: "220 mail.example.com ESMTP Courier 1.0.16"
	if strings.Contains(bannerLower, "courier") {
		re := regexp.MustCompile(`[Cc]ourier[^0-9]*([0-9._-]+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "Courier " + matches[1]
		}
		return "Courier"
	}

	// Microsoft ESMTP: "220 mail.example.com Microsoft ESMTP MAIL Service"
	if strings.Contains(bannerLower, "microsoft") || strings.Contains(bannerLower, "exchange") {
		re := regexp.MustCompile(`[Mm]icrosoft.*[Ee][Ss][Mm][Tt][Pp][^0-9]*([0-9._-]+)?`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 && matches[1] != "" {
			return "Microsoft ESMTP " + matches[1]
		}
		return "Microsoft ESMTP"
	}

	// Generic ESMTP: "220 mail.example.com ESMTP Service 1.2.3"
	re := regexp.MustCompile(`220[^\n]*esmtp[^\n]*([A-Za-z][A-Za-z0-9_-]+)[^0-9]*([0-9._-]+)?`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		if len(matches) > 2 && matches[2] != "" {
			return matches[1] + " " + matches[2]
		}
		return matches[1]
	}

	// Just extract the first word after 220
	re2 := regexp.MustCompile(`220\s+([\w.-]+)`)
	matches2 := re2.FindStringSubmatch(banner)
	if len(matches2) > 1 {
		return matches2[1]
	}

	return ""
}

// ExtractHTTPVersion extracts HTTP server version from banner
func ExtractHTTPVersion(banner string) string {
	// Try multiple formats: Server: nginx/1.18.0, Server: Apache/2.4
	re := regexp.MustCompile(`Server:\s*([\w/_-]+)\s*/?([\d.]+)?`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		if len(matches) > 2 && matches[2] != "" {
			return fmt.Sprintf("%s %s", matches[1], matches[2])
		}
		return matches[1]
	}
	// Try without Server: prefix
	re2 := regexp.MustCompile(`(nginx|apache|iis|lighttpd|cloudflare|openresty|caddy)/([\d.]+)`)
	matches2 := re2.FindStringSubmatch(strings.ToLower(banner))
	if len(matches2) > 2 {
		return fmt.Sprintf("%s %s", strings.Title(matches2[1]), matches2[2])
	}
	// Check for specific server strings
	if strings.Contains(strings.ToLower(banner), "nginx") {
		return "nginx"
	}
	if strings.Contains(strings.ToLower(banner), "apache") {
		return "Apache"
	}
	if strings.Contains(strings.ToLower(banner), "cloudflare") {
		return "Cloudflare"
	}
	return ""
}

// ExtractMySQLVersion extracts MySQL version from banner
func ExtractMySQLVersion(banner string) string {
	if len(banner) == 0 {
		return ""
	}

	// Handle binary MySQL handshake packet
	// First byte is protocol version:
	// 0x0a (10) = MySQL 4.1+
	// 0x09 (9) = MySQL 4.0
	// 0x08 (8) = MySQL 3.23
	protocolVer := byte(banner[0])

	// If this looks like a MySQL handshake packet
	if protocolVer == 0x0a || protocolVer == 0x09 || protocolVer == 0x08 {
		// Binary handshake - extract version string after protocol byte
		// The format is: [protocol_version:1 byte] [server_version:null_terminated_string] ...
		if len(banner) > 1 {
			// Find null terminator (0x00) for server version
			for i := 1; i < len(banner) && i < 100; i++ {
				if banner[i] == 0x00 {
					version := strings.TrimSpace(banner[1:i])
					if version != "" {
						return version
					}
					break
				}
			}
		}
	}

	// Try text-based version patterns (for text-based banners)
	bannerLower := strings.ToLower(banner)

	// Try multiple formats: 5.7.33, mysql 5.7.33, MariaDB
	re := regexp.MustCompile(`mysql[\s_-]*([\d.]+)`)
	matches := re.FindStringSubmatch(bannerLower)
	if len(matches) > 1 {
		return matches[1]
	}

	// Try MariaDB
	re2 := regexp.MustCompile(`mariadb[\s_-]*([\d.]+)`)
	matches2 := re2.FindStringSubmatch(bannerLower)
	if len(matches2) > 1 {
		return matches2[1]
	}

	// Try to find version pattern (look for patterns like 5.7.xx or 8.0.xx)
	re3 := regexp.MustCompile(`([5-9]\.[0-9]+(?:\.[0-9]+)?)`)
	matches3 := re3.FindStringSubmatch(banner)
	if len(matches3) > 1 {
		return matches3[1]
	}

	return ""
}

// ExtractPostgreSQLVersion extracts PostgreSQL version from banner
func ExtractPostgreSQLVersion(banner string) string {
	// Format: PostgreSQL 13.4
	re := regexp.MustCompile(`PostgreSQL\s+([\d.]+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractMSSQLVersion extracts MSSQL version from banner
func ExtractMSSQLVersion(banner string) string {
	// Format: Microsoft SQL Server 2019
	re := regexp.MustCompile(`SQL Server\s+(\d+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractOracleVersion extracts Oracle version from banner
func ExtractOracleVersion(banner string) string {
	// Format: Oracle Database 19c
	re := regexp.MustCompile(`Oracle\s+Database\s+(\w+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractRedisVersion extracts Redis version from banner
func ExtractRedisVersion(banner string) string {
	// Format: redis_version:6.2.6
	re := regexp.MustCompile(`redis_version:([\d.]+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractMongoDBVersion extracts MongoDB version from banner
func ExtractMongoDBVersion(banner string) string {
	// Format: 5.0.3
	re := regexp.MustCompile(`([\d.]+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractPOP3Version extracts POP3 version from banner
func ExtractPOP3Version(banner string) string {
	// Format: Dovecot pop3d
	re := regexp.MustCompile(`([\w]+)\s+pop3d`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractIMAPVersion extracts IMAP version from banner
func ExtractIMAPVersion(banner string) string {
	// Format: Dovecot imapd
	re := regexp.MustCompile(`([\w]+)\s+imapd`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractTelnetVersion extracts Telnet version from banner
func ExtractTelnetVersion(banner string) string {
	// Format: Debian-10+deb10u9
	re := regexp.MustCompile(`([\w.-]+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractVNCVersion extracts VNC version from banner
func ExtractVNCVersion(banner string) string {
	// Format: RFB 003.008
	re := regexp.MustCompile(`RFB\s+([\d.]+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractRDPVersion extracts RDP version from banner
func ExtractRDPVersion(banner string) string {
	// Format: Windows Server 2019
	re := regexp.MustCompile(`Windows\s+Server\s+(\d+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
// ExtractVersion is a generic router to extract version from banner based on service name
func ExtractVersion(service string, banner string) string {
	if banner == "" {
		return ""
	}

	serviceLower := strings.ToLower(service)

	switch {
	case strings.Contains(serviceLower, "ssh"):
		return ExtractSSHVersion(banner)
	case strings.Contains(serviceLower, "ftp"):
		return ExtractFTPVersion(banner)
	case strings.Contains(serviceLower, "smtp"):
		return ExtractSMTPVersion(banner)
	case strings.Contains(serviceLower, "http"):
		return ExtractHTTPVersion(banner)
	case strings.Contains(serviceLower, "mysql"):
		return ExtractMySQLVersion(banner)
	case strings.Contains(serviceLower, "postgresql"):
		return ExtractPostgreSQLVersion(banner)
	case strings.Contains(serviceLower, "mssql"):
		return ExtractMSSQLVersion(banner)
	case strings.Contains(serviceLower, "oracle"):
		return ExtractOracleVersion(banner)
	case strings.Contains(serviceLower, "redis"):
		return ExtractRedisVersion(banner)
	case strings.Contains(serviceLower, "mongodb"):
		return ExtractMongoDBVersion(banner)
	case strings.Contains(serviceLower, "pop3"):
		return ExtractPOP3Version(banner)
	case strings.Contains(serviceLower, "imap"):
		return ExtractIMAPVersion(banner)
	case strings.Contains(serviceLower, "telnet"):
		return ExtractTelnetVersion(banner)
	case strings.Contains(serviceLower, "vnc"):
		return ExtractVNCVersion(banner)
	case strings.Contains(serviceLower, "rdp"):
		return ExtractRDPVersion(banner)
	}

	return ""
}
