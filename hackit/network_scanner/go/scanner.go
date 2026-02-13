package main

import (
	"net"
	"strings"
	"time"
)

func IsAlive(host string, timeoutMs int) bool {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	
	// 1. Try TCP connect to port 80 (HTTP)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "80"), timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// 2. Try TCP connect to port 443 (HTTPS)
	conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, "443"), timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// 3. Try TCP connect to port 22 (SSH) - common on internal networks
	conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, "22"), timeout)
	if err == nil {
		conn.Close()
		return true
	}
	
	// 4. Try TCP connect to port 445 (SMB) - common on Windows
	conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, "445"), timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// ICMP requires raw sockets (root), skipping for portability
	// If we were running as root, we could use x/net/icmp
	
	return false
}

func LookupHost(ip string) string {
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}
