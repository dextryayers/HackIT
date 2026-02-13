package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func analyze(rustRes RustScanResult) map[string]TechInfo {
	techs := make(map[string]TechInfo)
	// Technology Detection Loop
	// Note: We use the detected technologies directly from RustScanResult
	// but we can add more logic here if needed.
	return techs
}

func AnalyzeTarget(targetURL string, opts *Options) (Result, error) {
	if !strings.HasPrefix(targetURL, "http") {
		if opts.HTTPS {
			targetURL = "https://" + targetURL
		} else {
			targetURL = "http://" + targetURL
		}
	}

	start := time.Now()

	// TLS Config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Transport Config
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(opts.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	// HTTP Client
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout) * time.Second,
	}

	if !opts.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return Result{}, err
	}

	// User-Agent
	if opts.RandomAgent {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	} else {
		req.Header.Set("User-Agent", "HackIt-TechHunter/1.0")
	}

	// Custom Headers
	for _, h := range opts.CustomHeader {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	res := Result{
		URL:          targetURL,
		Status:       resp.StatusCode,
		Headers:      make(map[string]string),
		Technologies: make(map[string]TechInfo),
		ResponseTime: time.Since(start),
	}

	// Collect Headers
	for k, v := range resp.Header {
		res.Headers[k] = strings.Join(v, ", ")
	}

	// IP Info
	host := req.URL.Hostname()
	ips, _ := net.LookupHost(host)
	if len(ips) > 0 {
		res.IPInfo.IP = ips[0]
		// In real world, query GeoIP here
		res.IPInfo.Country = "Detecting..."
		res.IPInfo.ISP = "Detecting..."
	}

	// TLS Info
	if resp.TLS != nil && opts.TLSInfo {
		cert := resp.TLS.PeerCertificates[0]
		res.TLSInfo = &TLSInfo{
			Version:            tlsVersionToString(resp.TLS.Version),
			Cipher:             tls.CipherSuiteName(resp.TLS.CipherSuite),
			Issuer:             cert.Issuer.CommonName,
			Subject:            cert.Subject.CommonName,
			Expiry:             cert.NotAfter.Format("2006-01-02 15:04:05"),
			SerialNumber:       cert.SerialNumber.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		}
	}

	// Body Analysis
	var body string
	if !opts.NoBody {
		bodyBytes, _ := io.ReadAll(resp.Body)
		body = string(bodyBytes)

		// Title Detection
		titleRe := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
		if matches := titleRe.FindStringSubmatch(body); len(matches) > 1 {
			res.Title = matches[1]
		}
	}

	// Technology Detection Loop
	// Handled by Rust engine
	return res, nil
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
