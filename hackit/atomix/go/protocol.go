package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type ProtocolResult struct {
	Target    string `json:"target"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	Open      bool   `json:"open"`
	Banner    string `json:"banner,omitempty"`
	TLSInfo   string `json:"tls_info,omitempty"`
	DNSInfo   string `json:"dns_info,omitempty"`
	Duration  string `json:"duration"`
}

type ProtocolScanner struct {
	Config     *ScanConfig
	Timeout    time.Duration
	Resolvers  []string
}

func NewProtocolScanner(cfg *ScanConfig) *ProtocolScanner {
	sc := &ProtocolScanner{
		Config:  cfg,
		Timeout: time.Duration(cfg.Timeout) * time.Second,
	}
	if cfg.Timeout <= 0 {
		sc.Timeout = 10 * time.Second
	}
	if cfg.DnsResolvers != "" {
		sc.Resolvers = strings.Split(cfg.DnsResolvers, ",")
	}
	return sc
}

func (p *ProtocolScanner) ScanTCP(host string, port int) ProtocolResult {
	start := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	res := ProtocolResult{Target: host, Protocol: "tcp", Port: port}

	conn, err := net.DialTimeout("tcp", addr, p.Timeout)
	if err != nil {
		res.Open = false
		res.Duration = time.Since(start).Round(time.Millisecond).String()
		return res
	}
	defer conn.Close()
	res.Open = true

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner := strings.TrimSpace(string(buf[:n]))
		if len(banner) > 200 {
			banner = banner[:200] + "..."
		}
		res.Banner = banner
	}

	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res
}

func (p *ProtocolScanner) ScanTLS(host string, port int) ProtocolResult {
	start := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	res := ProtocolResult{Target: host, Protocol: "tls", Port: port}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: p.Timeout},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		res.Open = false
		res.Duration = time.Since(start).Round(time.Millisecond).String()
		return res
	}
	defer conn.Close()
	res.Open = true

	state := conn.ConnectionState()
	var info []string
	if state.Version != 0 {
		version := fmt.Sprintf("TLS %d.%d", state.Version>>8, state.Version&0xff)
		info = append(info, version)
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info = append(info, fmt.Sprintf("CN=%s", cert.Subject.CommonName))
		info = append(info, fmt.Sprintf("issuer=%s", cert.Issuer.CommonName))
		if !cert.IsCA {
			info = append(info, fmt.Sprintf("expires=%s", cert.NotAfter.Format(time.RFC3339)))
		}
	}
	if len(info) > 0 {
		res.TLSInfo = strings.Join(info, ", ")
	}

	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res
}

func (p *ProtocolScanner) ScanDNS(host string) ProtocolResult {
	start := time.Now()
	res := ProtocolResult{Target: host, Protocol: "dns", Port: 53}

	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	var r net.Resolver
	if len(p.Resolvers) > 0 {
		r = net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: p.Timeout}
				return d.DialContext(ctx, network, p.Resolvers[0])
			},
		}
	}

	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		res.Open = false
		res.Duration = time.Since(start).Round(time.Millisecond).String()
		return res
	}
	res.Open = true

	cname, _ := r.LookupCNAME(ctx, host)
	var info []string
	if len(addrs) > 0 {
		info = append(info, fmt.Sprintf("A=%s", strings.Join(addrs, ",")))
	}
	if cname != "" {
		info = append(info, fmt.Sprintf("CNAME=%s", cname))
	}

	txts, _ := r.LookupTXT(ctx, host)
	if len(txts) > 0 {
		info = append(info, fmt.Sprintf("TXT=%s", strings.Join(txts, ",")))
	}
	if len(info) > 0 {
		res.DNSInfo = strings.Join(info, " | ")
	}

	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res
}

func (p *ProtocolScanner) ScanPortRange(host string, ports []int) []ProtocolResult {
	var results []ProtocolResult
	for _, port := range ports {
		r := p.ScanTCP(host, port)
		results = append(results, r)
		if r.Open && (port == 443 || port == 8443) {
			tlsResult := p.ScanTLS(host, port)
			results = append(results, tlsResult)
		}
	}
	return results
}

func PrintProtocolResults(results []ProtocolResult) {
	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "%s No protocol results\n", SColor(ColorYellow, "[!]"))
		return
	}

	fmt.Fprintf(os.Stderr, "\n%s Protocol Scan Results:\n", SColor(ColorBCyan, "►"))
	for _, r := range results {
		if !r.Open && r.Protocol != "dns" {
			continue
		}
		protoColor := ColorGreen
		if !r.Open { protoColor = ColorRed
		} else if r.Protocol == "tls" { protoColor = ColorYellow }

		fmt.Fprintf(os.Stderr, "  %s %s/%s\n",
			SColor(protoColor, fmt.Sprintf("[%s]", strings.ToUpper(r.Protocol))),
			r.Target,
			SColor(protoColor, fmt.Sprintf("%d", r.Port)))

		if r.Open {
			if r.Banner != "" {
				fmt.Fprintf(os.Stderr, "     Banner: %s\n", r.Banner)
			}
			if r.TLSInfo != "" {
				fmt.Fprintf(os.Stderr, "     TLS: %s\n", r.TLSInfo)
			}
			if r.DNSInfo != "" {
				fmt.Fprintf(os.Stderr, "     DNS: %s\n", r.DNSInfo)
			}
		}
		fmt.Fprintf(os.Stderr, "     Duration: %s\n", r.Duration)
	}
}

func HandleProtocolScan(cfg *ScanConfig) {
	if cfg.URL == "" || cfg.Protocol == "" {
		return
	}
	scanner := NewProtocolScanner(cfg)
	host := extractHost(cfg.URL)

	var results []ProtocolResult
	proto := strings.ToLower(cfg.Protocol)

	if proto == "dns" || proto == "all" {
		r := scanner.ScanDNS(host)
		results = append(results, r)
	}
	if proto == "tcp" || proto == "all" {
		commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
			993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
			8080, 8443, 9000, 9090, 27017, 27018}
		results = append(results, scanner.ScanPortRange(host, commonPorts)...)
	}
	if proto == "tls" || proto == "all" {
		for _, port := range []int{443, 8443, 465, 993, 995, 1433, 3306} {
			r := scanner.ScanTLS(host, port)
			results = append(results, r)
		}
	}

	PrintProtocolResults(results)
}

func extractHost(urlStr string) string {
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	if idx := strings.Index(urlStr, "/"); idx > 0 {
		urlStr = urlStr[:idx]
	}
	if idx := strings.Index(urlStr, ":"); idx > 0 {
		urlStr = urlStr[:idx]
	}
	return urlStr
}
