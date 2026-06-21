package main

import (
	"strings"
)

func IdentifyService(port int, banner string, host string) (string, string) {
	return DetectService(port, banner, host)
}

func ExtractVersion(service string, banner string) string {
	switch strings.ToLower(service) {
	case "ssh":
		return ExtractSSHVersion(banner)
	case "http", "nginx", "apache", "iis":
		return ExtractHTTPVersion(banner)
	case "ftp":
		return ExtractFTPVersion(banner)
	case "smtp":
		return ExtractSMTPVersion(banner)
	case "mysql":
		return ExtractMySQLVersion(banner)
	case "redis":
		return ExtractRedisVersion(banner)
	}
	return ""
}

func matchServiceFromBanner(banner string) (string, string) {
	sig := MatchServiceSignatures(0, banner)
	if sig != nil {
		return sig.Product, sig.Version
	}
	return "", ""
}

func DetectService(port int, banner string, host string) (string, string) {
	return DetectServiceV2(port, banner, host)
}

func ExtractFTPVersion(banner string) string {
	if strings.Contains(banner, "vsFTPd") {
		return extractBetween(banner, "vsFTPd", " ")
	}
	if strings.Contains(banner, "ProFTPD") {
		return extractBetween(banner, "ProFTPD", " ")
	}
	if strings.Contains(banner, "pure-ftpd") {
		idx := strings.Index(banner, "pure-ftpd")
		rest := banner[idx+9:]
		parts := strings.Fields(rest)
		if len(parts) > 0 {
			return strings.TrimRight(parts[0], ")")
		}
	}
	return ""
}

func ExtractSSHVersion(banner string) string {
	idx := strings.Index(banner, "OpenSSH_")
	if idx >= 0 {
		rest := banner[idx+8:]
		parts := strings.SplitN(rest, " ", 2)
		if len(parts) > 0 {
			return strings.TrimRight(parts[0], " ")
		}
	}
	return ""
}

func ExtractHTTPVersion(banner string) string {
	lower := strings.ToLower(banner)
	if strings.Contains(lower, "nginx/") {
		return extractBetween(banner, "nginx/", " ")
	}
	if strings.Contains(lower, "apache/") {
		return extractBetween(banner, "Apache/", " ")
	}
	if strings.Contains(lower, "microsoft-iis/") || strings.Contains(lower, "iis/") {
		return extractBetween(strings.ToLower(banner), "iis/", " ")
	}
	return ""
}

func ExtractSMTPVersion(banner string) string {
	if strings.Contains(banner, "Postfix") {
		return extractBetween(banner, "Postfix", " ")
	}
	if strings.Contains(banner, "Exim") {
		return extractBetween(banner, "Exim", " ")
	}
	return ""
}

func ExtractMySQLVersion(banner string) string {
	return extractBetween(banner, "mysql", " ")
}

func ExtractRedisVersion(banner string) string {
	idx := strings.Index(banner, "redis_version:")
	if idx >= 0 {
		rest := banner[idx+14:]
		parts := strings.Fields(rest)
		if len(parts) > 0 {
			return strings.TrimRight(parts[0], "\r\n")
		}
	}
	return ""
}

func extractBetween(s, prefix, suffix string) string {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	rest := s[start:]
	if suffix == " " {
		parts := strings.Fields(rest)
		if len(parts) > 0 {
			return strings.TrimRight(parts[0], "\r\n,;")
		}
		return ""
	}
	end := strings.Index(rest, suffix)
	if end < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}
