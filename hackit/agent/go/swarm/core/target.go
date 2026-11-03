package core

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// TargetKind classifies what the operator actually gave us.
type TargetKind string

const (
	TargetDomain  TargetKind = "domain"
	TargetIPv4    TargetKind = "ipv4"
	TargetIPv6    TargetKind = "ipv6"
	TargetCIDR    TargetKind = "cidr"
	TargetLocal   TargetKind = "local"
	TargetUnknown TargetKind = "unknown"
)

// ParsedTarget is the normalized view every agent consumes instead of the raw
// operator string.
type ParsedTarget struct {
	Raw       string     `json:"raw"`
	Host      string     `json:"host"`
	Kind      TargetKind `json:"kind"`
	IsPrivate bool       `json:"is_private"`
	IsURL     bool       `json:"is_url"`
	Scheme    string     `json:"scheme"`
	Port      string     `json:"port"`
	BaseURL   string     `json:"base_url"`
	ScanSeeds []string   `json:"scan_seeds"`
}

// ParseTarget normalizes operator input once so no agent re-parses it.
// Accepts: https://example.com/path, example.com:8443, 1.2.3.4,
// 192.168.1.0/24, [::1]:8080, localhost.
func ParseTarget(raw string) ParsedTarget {
	pt := ParsedTarget{Raw: strings.TrimSpace(raw), Kind: TargetUnknown}
	in := pt.Raw
	if in == "" {
		return pt
	}

	if strings.Contains(in, "://") {
		pt.IsURL = true
		if u, err := url.Parse(in); err == nil && u.Hostname() != "" {
			pt.Scheme = strings.ToLower(u.Scheme)
			pt.Host = strings.ToLower(u.Hostname())
			pt.Port = u.Port()
			if pt.Scheme == "" {
				pt.Scheme = "https"
			}
		} else {
			in = strings.TrimSpace(strings.SplitN(in, "://", 2)[1])
			pt.IsURL = false
		}
	}
	if pt.Host == "" {
		h := in
		// A CIDR's slash is address syntax, not a path separator.
		if _, _, err := net.ParseCIDR(h); err != nil {
			for _, cut := range []string{"/", "?", "#"} {
				if i := strings.Index(h, cut); i >= 0 {
					h = h[:i]
				}
			}
		}
		h = strings.TrimSpace(h)
		if strings.HasPrefix(h, "[") {
			if i := strings.Index(h, "]"); i >= 0 {
				pt.Port = strings.TrimPrefix(h[i+1:], ":")
				pt.Host = h[1:i]
			} else {
				pt.Host = h
			}
		} else if host, port, err := net.SplitHostPort(h); err == nil {
			pt.Host, pt.Port = strings.ToLower(host), port
		} else {
			pt.Host = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(h, "*."), "."))
		}
	}
	if pt.Host == "" {
		return pt
	}

	if _, ipnet, err := net.ParseCIDR(pt.Host); err == nil {
		pt.Kind = TargetCIDR
		pt.IsPrivate = isPrivateNet(ipnet.IP)
		pt.ScanSeeds = expandCIDR(ipnet)
		pt.BaseURL = pt.baseURL()
		return pt
	}

	if ip := net.ParseIP(strings.Trim(pt.Host, "[]")); ip != nil {
		pt.Host = strings.Trim(pt.Host, "[]")
		pt.IsPrivate = isPrivateNet(ip)
		if ip.To4() != nil {
			pt.Kind = TargetIPv4
		} else {
			pt.Kind = TargetIPv6
		}
		if isLocalName(pt.Host) {
			pt.Kind = TargetLocal
		}
		pt.ScanSeeds = []string{pt.Host}
		pt.BaseURL = pt.baseURL()
		return pt
	}

	if isLocalName(pt.Host) {
		pt.Kind = TargetLocal
		pt.IsPrivate = true
	} else {
		pt.Kind = TargetDomain
	}
	pt.ScanSeeds = []string{pt.Host}
	pt.BaseURL = pt.baseURL()
	return pt
}

func (pt ParsedTarget) baseURL() string {
	scheme := pt.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := pt.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if pt.Port != "" {
		return fmt.Sprintf("%s://%s:%s", scheme, host, pt.Port)
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// DisplayHost is the canonical host agents log and scan.
func (pt ParsedTarget) DisplayHost() string {
	if pt.Host != "" {
		return pt.Host
	}
	return pt.Raw
}

func isLocalName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || h == "ip6-localhost" {
		return true
	}
	for _, suffix := range []string{".local", ".lan", ".internal", ".intranet", ".home", ".corp"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		return isPrivateNet(ip)
	}
	return false
}

func isPrivateNet(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	if ip.To4() == nil && len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

// expandCIDR lists usable hosts, capped so a /8 can never blow up the scan.
// shortcut: /28+ fully listed, larger ranges capped at 256 hosts; widen when agent concurrency grows.
func expandCIDR(ipnet *net.IPNet) []string {
	ones, _ := ipnet.Mask.Size()
	base := ipnet.IP
	var seeds []string
	if ones >= 28 {
		for ip := dupIP(base.Mask(ipnet.Mask)); ipnet.Contains(ip); incIP(ip) {
			seeds = append(seeds, ip.String())
		}
		return seeds
	}
	ip := dupIP(base.Mask(ipnet.Mask))
	for i := 0; i < 256 && ipnet.Contains(ip); i++ {
		seeds = append(seeds, ip.String())
		incIP(ip)
	}
	return seeds
}

func dupIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
