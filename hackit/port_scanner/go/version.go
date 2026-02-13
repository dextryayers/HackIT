package main

import (
	"regexp"
	"strings"
)

func ExtractVersion(service string, banner string) string {
	b := strings.ReplaceAll(banner, "\r", "")

	switch strings.ToLower(service) {
	case "http", "https", "http-proxy", "http-alt", "https-alt":
		for _, line := range strings.Split(b, "\n") {
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(trimmedLine), "server:") {
				return strings.TrimSpace(trimmedLine[len("server:"):])
			}
		}
	}

	if strings.Contains(strings.ToLower(b), "openssh") {
		re := regexp.MustCompile(`OpenSSH[_/ ]([0-9][0-9\.p\-]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 1 {
			return "OpenSSH " + m[1]
		}
	}
	if strings.Contains(strings.ToLower(b), "ssh-") {
		// Generic SSH version string: SSH-2.0-OpenSSH_8.2p1
		re := regexp.MustCompile(`SSH-[0-9\.]+-([A-Za-z0-9\._\-]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 1 {
			return m[1]
		}
	}
	if strings.Contains(strings.ToLower(b), "exim") {
		re := regexp.MustCompile(`Exim ([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 1 {
			return "Exim " + m[1]
		}
	}
	if strings.Contains(strings.ToLower(b), "postfix") {
		return "Postfix"
	}
	if strings.Contains(strings.ToLower(b), "vsftpd") {
		re := regexp.MustCompile(`vsftpd[^\d]*([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 1 {
			return "vsftpd " + m[1]
		}
	}
	if strings.Contains(strings.ToLower(b), "redis") {
		re := regexp.MustCompile(`redis[_ ]version[: ]([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(strings.ToLower(b)); len(m) > 1 {
			return "Redis " + m[1]
		}
	}
	if strings.Contains(strings.ToLower(b), "mysql") || strings.Contains(strings.ToLower(b), "mariadb") {
		re := regexp.MustCompile(`(mysql|mariadb)[^\d]*([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(strings.ToLower(b)); len(m) > 2 {
			return strings.Title(m[1]) + " " + m[2]
		}
	}
	if strings.Contains(strings.ToLower(b), "postgre") {
		re := regexp.MustCompile(`postgres(?:ql)?[^\d]*([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(strings.ToLower(b)); len(m) > 1 {
			return "PostgreSQL " + m[1]
		}
	}
	if strings.Contains(strings.ToLower(b), "dovecot") {
		re := regexp.MustCompile(`dovecot[^\d]*([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(strings.ToLower(b)); len(m) > 1 {
			return "Dovecot " + m[1]
		}
	}
	if strings.Contains(strings.ToLower(b), "imap") || strings.Contains(strings.ToLower(b), "pop3") {
		re := regexp.MustCompile(`(imap|pop3)[^\d]*([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(strings.ToLower(b)); len(m) > 2 {
			return strings.ToUpper(m[1]) + " " + m[2]
		}
	}

	// Generic: product/version pattern
	re := regexp.MustCompile(`([A-Za-z][A-Za-z0-9\-_]+)[/ ]([0-9][0-9\.]+)`)
	if m := re.FindStringSubmatch(b); len(m) > 2 {
		return m[1] + " " + m[2]
	}

	if strings.Contains(strings.ToLower(b), "dovecot") {
		return "Dovecot"
	}
	if strings.Contains(strings.ToLower(b), "proftpd") {
		return "ProFTPD"
	}
	if strings.Contains(strings.ToLower(b), "iis") || strings.Contains(strings.ToLower(b), "microsoft-iis") {
		re := regexp.MustCompile(`Microsoft-IIS/([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 1 {
			return "Microsoft IIS " + m[1]
		}
		return "Microsoft IIS"
	}
	if strings.Contains(strings.ToLower(b), "apache") {
		re := regexp.MustCompile(`Apache/([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 1 {
			return "Apache " + m[1]
		}
		return "Apache"
	}
	if strings.Contains(strings.ToLower(b), "nginx") {
		re := regexp.MustCompile(`nginx/([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 1 {
			return "nginx " + m[1]
		}
		return "nginx"
	}

	if strings.Contains(strings.ToLower(b), "mongodb") || strings.Contains(strings.ToLower(b), "mongo") {
		re := regexp.MustCompile(`version[: ]*"?([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(strings.ToLower(b)); len(m) > 1 {
			return "MongoDB " + m[1]
		}
		return "MongoDB"
	}
	if strings.Contains(strings.ToLower(b), "memcached") {
		re := regexp.MustCompile(`VERSION ([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 1 {
			return "Memcached " + m[1]
		}
		return "Memcached"
	}
	if strings.Contains(strings.ToLower(b), "microsoft-iis") || strings.Contains(strings.ToLower(b), "iis") {
		re := regexp.MustCompile(`IIS/([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 1 {
			return "IIS " + m[1]
		}
		return "IIS"
	}
	if strings.Contains(strings.ToLower(b), "ftp") {
		re := regexp.MustCompile(`([A-Za-z0-9\-]+FTP[d]?)[ /]([0-9][0-9\.]+)`)
		if m := re.FindStringSubmatch(b); len(m) > 2 {
			return m[1] + " " + m[2]
		}
	}

	return ""
}
