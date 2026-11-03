package native

import (
	"net"
	"strings"
	"time"
)

// InferASN resolves the host and classifies infra from real DNS answers,
// never from substrings of the domain name.
func InferASN(host string) (asn, infra string) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return classifyIP(host, ip), "Direct IP"
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "Unknown (DNS unresolved)", "Unknown"
	}
	var v4 net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = ip
			break
		}
	}
	if v4 == nil {
		v4 = ips[0]
	}
	return classifyIP(host, v4), infraFromNames(ptrNames(v4.String()))
}

func ptrNames(ip string) []string {
	c := make(chan []string, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		if err != nil {
			c <- nil
			return
		}
		c <- names
	}()
	select {
	case n := <-c:
		return n
	case <-time.After(4 * time.Second):
		return nil
	}
}

func infraFromNames(names []string) string {
	if len(names) == 0 {
		return "Origin (no CDN PTR)"
	}
	joined := strings.ToLower(strings.Join(names, " "))
	switch {
	case strings.Contains(joined, "amazonaws.com") || strings.Contains(joined, "aws"):
		return "AWS"
	case strings.Contains(joined, "google") || strings.Contains(joined, "gcp") || strings.Contains(joined, "googleusercontent"):
		return "GCP"
	case strings.Contains(joined, "azure") || strings.Contains(joined, "cloudapp") || strings.Contains(joined, "microsoft"):
		return "Azure"
	case strings.Contains(joined, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(joined, "akamai"):
		return "Akamai"
	case strings.Contains(joined, "fastly"):
		return "Fastly"
	default:
		parts := strings.Split(strings.TrimSuffix(names[0], "."), ".")
		if len(parts) >= 2 {
			return "Origin (" + strings.Join(parts[len(parts)-2:], ".") + ")"
		}
		return "Origin"
	}
}

func classifyIP(host string, ip net.IP) string {
	if ip.IsLoopback() {
		return "Loopback (local)"
	}
	if ip.IsPrivate() {
		return "RFC1918 (intranet)"
	}
	if ip.IsLinkLocalUnicast() {
		return "Link-local"
	}
	return "Direct IP " + ip.String()
}
