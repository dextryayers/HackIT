package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

type ConnectionConfig struct {
	Timeout   int
	Delay     int
	Retries   int
	MaxRate   float64
	Proxy     string
	Proxies   []string
	ProxyAuth string
	Tor       bool
	Interface string
	HTTP2     bool
}

func SetupConnection(config *ScanConfig) *http.Client {
	resolveTargetOnce(config)

	dialer := &net.Dialer{
		Timeout:   time.Duration(config.Timeout) * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	if config.Interface != "" {
		if ip := net.ParseIP(config.Interface); ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}

	connsPerHost := config.Threads * 2
	if connsPerHost < 16 {
		connsPerHost = 16
	}
	if connsPerHost > 256 {
		connsPerHost = 256
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384,
			},
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
				port = "443"
				if strings.HasPrefix(config.Target, "http://") {
					port = "80"
				}
			}
			// Use the cached address for the target host; other hosts
			// (proxy, redirect target) resolve normally. Host header and
			// TLS SNI stay tied to the URL host, so vhosts still work.
			dialHost := host
			if host == resolvedHost && len(resolvedIPs) > 0 {
				if ip := nextDialIP(); ip != "" {
					dialHost = ip
				}
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(dialHost, port))
			if err != nil {
				return nil, err
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetNoDelay(true)
				_ = tcpConn.SetKeepAlive(true)
				_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}
			return conn, nil
		},
		MaxIdleConns:          connsPerHost * 2,
		MaxConnsPerHost:       connsPerHost,
		MaxIdleConnsPerHost:   connsPerHost,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
		DisableKeepAlives:     false,
		WriteBufferSize:       32 * 1024,
		ReadBufferSize:        32 * 1024,
		ForceAttemptHTTP2:     config.HTTP2,
		TLSHandshakeTimeout:   time.Duration(config.Timeout) * time.Second,
		ResponseHeaderTimeout: time.Duration(config.Timeout) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	ApplyProxy(transport, config)

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if config.FollowRedirect && len(via) < 5 {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	return client
}

// Resolved target host and its addresses, cached once per target so a 30k
// wordlist does not pay a DNS lookup per request. A dead domain is detected
// here and reported immediately instead of timing out 30k times.
var (
	resolvedHost string
	resolvedIPs  []string
	dialCounter  uint64
)

func resolveTargetOnce(config *ScanConfig) (bool, string) {
	resolvedHost = ""
	resolvedIPs = nil
	if config.Target == "" {
		return true, ""
	}
	u, err := url.Parse(config.Target)
	if err != nil || u.Hostname() == "" {
		return false, "invalid URL: " + config.Target
	}
	host := u.Hostname()
	if config.IP != "" {
		resolvedHost = host
		resolvedIPs = []string{config.IP}
		return true, config.IP
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(maxInt(config.Timeout, 3))*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		msg := "DNS failed for " + host
		if err != nil {
			msg += ": " + err.Error()
		}
		return false, msg
	}
	var v4 []string
	for _, a := range addrs {
		if !strings.Contains(a, ":") {
			v4 = append(v4, a)
		}
	}
	if len(v4) > 0 {
		resolvedIPs = v4
	} else {
		resolvedIPs = addrs
	}
	resolvedHost = host
	return true, resolvedIPs[0]
}

func nextDialIP() string {
	if len(resolvedIPs) == 0 {
		return ""
	}
	i := atomic.AddUint64(&dialCounter, 1)
	return resolvedIPs[int(i)%len(resolvedIPs)]
}

func ApplyProxy(transport *http.Transport, config *ScanConfig) {
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			if config.ProxyAuth != "" {
				parts := strings.SplitN(config.ProxyAuth, ":", 2)
				if len(parts) == 2 {
					proxyURL.User = url.UserPassword(parts[0], parts[1])
				}
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	} else if config.Tor {
		transport.Proxy = http.ProxyURL(&url.URL{
			Scheme: "socks5",
			Host:   "127.0.0.1:9050",
		})
	} else if config.ProxiesFile != "" {
		proxies := LoadProxies(config.ProxiesFile)
		if len(proxies) > 0 {
			proxyURL, _ := url.Parse(proxies[rand.Intn(len(proxies))])
			if proxyURL != nil {
				transport.Proxy = http.ProxyURL(proxyURL)
			}
		}
	}
}

func LoadProxies(path string) []string {
	var proxies []string
	file, err := os.Open(path)
	if err != nil {
		return proxies
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "http") && !strings.HasPrefix(line, "socks") {
				line = "http://" + line
			}
			proxies = append(proxies, line)
		}
	}
	return proxies
}

func ValidateConnectivity(target string, client *http.Client) (bool, string) {
	parsed, err := url.Parse(target)
	if err != nil {
		return false, "invalid URL: " + err.Error()
	}
	host := parsed.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	addrs, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil {
		return false, "DNS failed: " + err.Error()
	}
	var ipInfo string
	for _, a := range addrs {
		if !strings.Contains(a, ":") {
			ipInfo = a
			break
		}
	}
	if ipInfo == "" && len(addrs) > 0 {
		ipInfo = addrs[0]
		if strings.Contains(ipInfo, "64:ff9b::") {
			return false, "NAT64, use --proxy"
		}
	}

	req, _ := http.NewRequest("GET", target, nil)
	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "timeout") {
			return false, "timeout to " + host + " (" + ipInfo + ")"
		}
		if strings.Contains(errStr, "refused") {
			return false, "refused by " + host + " (" + ipInfo + ")"
		}
		return false, errStr
	}
	defer resp.Body.Close()

	info := host + " (" + ipInfo + ") [" + resp.Proto + "]"
	return true, info
}

func PrintConnectionInfo(config *ScanConfig) {
	fmt.Fprintf(color.Output, "%s Timeout: %ds | Retries: %d\n",
		color.CyanString("[*]"), config.Timeout, config.Retries)
	if config.Proxy != "" {
		fmt.Fprintf(color.Output, "%s Proxy: %s\n", color.CyanString("[*]"), maskProxy(config.Proxy))
	}
	if config.Tor {
		fmt.Fprintf(color.Output, "%s Tor: enabled (127.0.0.1:9050)\n", color.CyanString("[*]"))
	}
	if config.Delay > 0 {
		fmt.Fprintf(color.Output, "%s Delay: %dms\n", color.CyanString("[*]"), config.Delay)
	}
	if config.MaxRate > 0 {
		fmt.Fprintf(color.Output, "%s Max rate: %.1f req/s\n", color.CyanString("[*]"), config.MaxRate)
	}
	if config.Stealth {
		fmt.Fprintf(color.Output, "%s Stealth: UA rotation + forwarding-header spoof\n", color.GreenString("[+]"))
	}
	if config.WAFBypass {
		fmt.Fprintf(color.Output, "%s WAF bypass: on (403/406/429/503 retried with mutations)\n", color.GreenString("[+]"))
	}
}

func maskProxy(proxy string) string {
	if strings.Contains(proxy, "@") {
		parts := strings.SplitN(proxy, "@", 2)
		return parts[0][:strings.Index(parts[0], ":")+1] + "***@" + parts[1]
	}
	return proxy
}
