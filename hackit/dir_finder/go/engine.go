package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func CreateClient(config *ScanConfig) *http.Client {
	dialer := &net.Dialer{
		Timeout:   time.Duration(config.Timeout) * time.Second,
		KeepAlive: 15 * time.Second,
		DualStack: false,
	}

	if config.Interface != "" {
		dialer.LocalAddr = &net.TCPAddr{
			IP: net.ParseIP(config.Interface),
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
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
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			var dialAddr string
			for _, a := range addrs {
				if strings.Contains(a, ":") {
					continue
				}
				dialAddr = a
				break
			}
			if dialAddr == "" && len(addrs) > 0 {
				dialAddr = addrs[0]
			}
			if dialAddr == "" {
				return nil, fmt.Errorf("no resolved addresses for %s", host)
			}
			return dialer.DialContext(ctx, network, dialAddr+":"+port)
		},
		MaxIdleConns:        50,
		MaxConnsPerHost:     25,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		DisableKeepAlives:   false,
	}

	if config.HTTP2 {
		transport.ForceAttemptHTTP2 = true
	} else {
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Timeout:   time.Duration(config.Timeout) * time.Second,
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

func checkConnectivity(target string, client *http.Client) (bool, string) {
	parsed, err := url.Parse(target)
	if err != nil {
		return false, "invalid URL: " + err.Error()
	}
	host := parsed.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ctx := context.Background()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return false, "DNS lookup failed for " + host + ": " + err.Error()
	}
	var ipv4Addrs, ipv6Addrs []string
	for _, a := range addrs {
		if strings.Contains(a, ":") {
			ipv6Addrs = append(ipv6Addrs, a)
		} else {
			ipv4Addrs = append(ipv4Addrs, a)
		}
	}
	addrInfo := ""
	if len(ipv4Addrs) > 0 {
		addrInfo = ipv4Addrs[0]
	} else if len(ipv6Addrs) > 0 {
		addrInfo = ipv6Addrs[0]
	}
	if len(ipv6Addrs) > 0 && len(ipv4Addrs) == 0 {
		if strings.Contains(addrInfo, "64:ff9b::") {
			return false, "NAT64 detected (" + addrInfo + "). Use --proxy to bypass IPv6-to-IPv4 translation"
		}
	}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false, "request creation failed: " + err.Error()
	}
	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
			return false, "connection timeout to " + host + " (" + addrInfo + ")"
		}
		if strings.Contains(errStr, "refused") {
			return false, "connection refused by " + host + " (" + addrInfo + ")"
		}
		if strings.Contains(errStr, "reset") {
			if len(ipv6Addrs) > 0 && len(ipv4Addrs) == 0 {
				return false, "connection reset via IPv6/NAT64 (" + addrInfo + "). Try: --proxy http://proxy:port"
			}
			return false, "connection reset by " + host + " (" + addrInfo + "). Use -t 5 to reduce threads"
		}
		if strings.Contains(errStr, "no route") || strings.Contains(errStr, "unreachable") {
			return false, "no route to " + host + " (" + addrInfo + ")"
		}
		return false, errStr
	}
	defer resp.Body.Close()

	baseInfo := host + " (" + addrInfo + ") [" + resp.Proto + "] " + fmtStatus(resp.StatusCode)

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			if !strings.HasPrefix(loc, "http") {
				if strings.HasPrefix(loc, "/") {
					loc = parsed.Scheme + "://" + parsed.Host + loc
				} else {
					loc = parsed.Scheme + "://" + parsed.Host + "/" + loc
				}
			}
			baseInfo += " -> " + loc
		}
	}

	return true, baseInfo
}

func fmtStatus(code int) string {
	return fmt.Sprintf("%d", code)
}
