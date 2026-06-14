package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

type Endpoint struct {
	URL    string
	Scheme string
	Host   string
	Port   string
	Alive  bool
}

func ProbeEndpoint(rawURL string, timeout int) *Endpoint {
	u, err := url.Parse(rawURL)
	if err != nil {
		u = &url.URL{Scheme: "https", Host: rawURL}
	}
	host := u.Hostname()
	port := u.Port()

	endpoints := []*Endpoint{}
	schemes := []string{"https", "http"}

	if port != "" {
		for _, s := range schemes {
			endpoints = append(endpoints, &Endpoint{
				URL:    fmt.Sprintf("%s://%s:%s", s, host, port),
				Scheme: s, Host: host, Port: port,
			})
		}
	} else {
		portMap := map[string]string{"https": "443", "http": "80"}
		for _, s := range schemes {
			p := portMap[s]
			endpoints = append(endpoints, &Endpoint{
				URL:    fmt.Sprintf("%s://%s:%s", s, host, p),
				Scheme: s, Host: host, Port: p,
			})
		}
	}

	for _, ep := range endpoints {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ep.Host, ep.Port),
			time.Duration(timeout)*time.Second)
		if err == nil {
			conn.Close()
			ep.Alive = true
			return ep
		}
	}
	return endpoints[0]
}

func DetectProtocol(host string, timeout int) string {
	portMap := map[string]string{"https": "443", "http": "80"}
	for _, s := range []string{"https", "http"} {
		addr := net.JoinHostPort(host, portMap[s])
		conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
		if err == nil {
			conn.Close()
			return s
		}
	}
	return "https"
}

func ExtractHostname(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Hostname()
}

func EnsureScheme(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	return "https://" + raw
}
