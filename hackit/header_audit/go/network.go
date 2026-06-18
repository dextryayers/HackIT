package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func CreateClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func CreateNoRedirectClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func SetHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
}

func SetCORSPreflightHeaders(req *http.Request, origin string) {
	SetHeaders(req)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "content-type, authorization")
}

func ResolveIP(hostname string) string {
	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}

func CheckAllowedMethods(targetURL string) []string {
	var methods []string
	testMethods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"}

	client := CreateNoRedirectClient()
	for _, m := range testMethods {
		req, err := http.NewRequest(m, targetURL, nil)
		if err != nil {
			continue
		}
		SetHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 || resp.StatusCode == 405 || resp.StatusCode == 501 {
			methods = append(methods, m)
		}
	}
	return methods
}

func TraceRedirectChain(targetURL string) []RedirectStep {
	var chain []RedirectStep
	client := CreateNoRedirectClient()
	currentURL := targetURL

	for i := 0; i < 10; i++ {
		req, err := http.NewRequest("GET", currentURL, nil)
		if err != nil {
			break
		}
		SetHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			break
		}

		step := RedirectStep{URL: currentURL, Status: resp.StatusCode}
		for k, v := range resp.Header {
			val := strings.Join(v, ", ")
			desc, cat := GetHeaderMetadata(k)
			step.Headers = append(step.Headers, HeaderInfo{
				Key: k, Value: val, Description: desc, Category: cat,
				IsSecurity: cat == "Security" || cat == "Security/CORS",
			})
		}
		chain = append(chain, step)

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			resp.Body.Close()
			break
		}

		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if loc == "" {
			break
		}

		currentURL = resolveRedirectURL(currentURL, loc)
	}

	return chain
}

func resolveRedirectURL(base, loc string) string {
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc
	}
	u, err := url.Parse(base)
	if err != nil {
		return loc
	}
	if strings.HasPrefix(loc, "/") {
		return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, loc)
	}
	baseDir := u.Path
	if strings.LastIndex(baseDir, "/") > 0 {
		baseDir = baseDir[:strings.LastIndex(baseDir, "/")]
	}
	return fmt.Sprintf("%s://%s%s/%s", u.Scheme, u.Host, baseDir, loc)
}

func PerformCORSPreflight(targetURL, origin string) *http.Response {
	client := CreateNoRedirectClient()
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		return nil
	}
	SetCORSPreflightHeaders(req, origin)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	return resp
}

func PerformOPTIONS(targetURL string) *http.Response {
	client := CreateNoRedirectClient()
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		return nil
	}
	SetHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	return resp
}

func GetTLSConnectionState(targetURL string) *tls.ConnectionState {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	if u.Scheme != "https" {
		return nil
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return &state
}

func ExtractHeaderList(headers map[string][]string) []HeaderInfo {
	var result []HeaderInfo
	for k, v := range headers {
		val := strings.Join(v, ", ")
		desc, cat := GetHeaderMetadata(k)
		result = append(result, HeaderInfo{
			Key:         k,
			Value:       val,
			Description: desc,
			Category:    cat,
			IsSecurity:  cat == "Security" || cat == "Security/CORS" || cat == "Security/Session",
		})
	}
	return result
}
