package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

func CreateClient(config *ScanConfig) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        100,
		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	if config.HTTP2 {
		transport.ForceAttemptHTTP2 = true
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	if config.Interface != "" {
		dialer := &net.Dialer{
			Timeout:   time.Duration(config.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
			LocalAddr: &net.TCPAddr{
				IP: net.ParseIP(config.Interface),
			},
		}
		transport.DialContext = dialer.DialContext
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
