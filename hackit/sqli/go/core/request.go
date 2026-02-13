package core

import (
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
}

func (e *Engine) Request(payload string, param string) (string, int, http.Header, error) {
	// Stealth mode: Random delay
	if e.Opts.Stealth {
		jitter := rand.Intn(1000)
		time.Sleep(time.Duration(e.Opts.Delay+jitter) * time.Millisecond)
	} else if e.Opts.Delay > 0 {
		time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
	}
	var body io.Reader
	u, err := url.Parse(e.Opts.URL)
	if err != nil {
		return "", 0, nil, err
	}

	// Smart parameter injection
	if e.Opts.Method == "GET" || e.Opts.Method == "" {
		q := u.Query()
		if param != "" {
			q.Set(param, payload)
		}
		u.RawQuery = q.Encode()
	} else {
		if e.Opts.Data != "" && param != "" {
			vals, _ := url.ParseQuery(e.Opts.Data)
			vals.Set(param, payload)
			body = strings.NewReader(vals.Encode())
		} else if e.Opts.Data != "" {
			body = strings.NewReader(e.Opts.Data)
		}
	}

	targetURL := u.String()
	req, err := http.NewRequest(e.Opts.Method, targetURL, body)
	if err != nil {
		return "", 0, nil, err
	}

	// Set Headers
	for _, h := range e.Opts.Header {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	if e.Opts.Agent != "" {
		req.Header.Set("User-Agent", e.Opts.Agent)
	} else if e.Opts.Stealth {
		// Rotate User-Agent in stealth mode
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
		// Add fake headers to look more like a browser
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Sec-Ch-Ua", "\"Google Chrome\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\"")
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}
	if e.Opts.Cookie != "" {
		req.Header.Set("Cookie", e.Opts.Cookie)
	}
	if e.Opts.Referer != "" {
		req.Header.Set("Referer", e.Opts.Referer)
	}

	resp, err := e.Client.Do(req)
	if err != nil {
		e.Log.Critical(err.Error())
		return "", 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, nil, err
	}

	return string(respBody), len(respBody), resp.Header, nil
}
