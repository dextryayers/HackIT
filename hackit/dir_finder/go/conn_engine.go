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
	"time"

	"github.com/fatih/color"
)

type ConnectionConfig struct {
	Timeout    int
	Delay      int
	Retries    int
	MaxRate    float64
	Proxy      string
	Proxies    []string
	ProxyAuth  string
	Tor        bool
	Interface  string
	HTTP2      bool
}

func SetupConnection(config *ScanConfig) *http.Client {
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

	connsPerHost := config.Threads * 5
	if connsPerHost < 10 {
		connsPerHost = 10
	}
	if connsPerHost > 100 {
		connsPerHost = 100
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
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
			return dialer.DialContext(ctx, network, host+":"+port)
		},
		MaxIdleConns:        connsPerHost * 2,
		MaxConnsPerHost:     connsPerHost,
		MaxIdleConnsPerHost: connsPerHost,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		DisableKeepAlives:   false,
		WriteBufferSize:     4096,
		ReadBufferSize:      8192,
	}

	if config.HTTP2 {
		transport.ForceAttemptHTTP2 = true
	} else {
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}

	ApplyProxy(transport, config)

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
}

func maskProxy(proxy string) string {
	if strings.Contains(proxy, "@") {
		parts := strings.SplitN(proxy, "@", 2)
		return parts[0][:strings.Index(parts[0], ":")+1] + "***@" + parts[1]
	}
	return proxy
}
