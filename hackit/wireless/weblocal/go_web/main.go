package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ── Config ──────────────────────────────────────────────────────────

var (
	port     = "8200"
	workerBin string
)

func init() {
	if p := os.Getenv("GO_WEB_PORT"); p != "" {
		port = p
	}
	// Auto-discover hackit-worker
	candidates := []string{
		"../go_workers/hackit-worker",
		"../go_workers/bin/hackit-worker",
	}
	self, _ := os.Executable()
	dir := filepath.Dir(self)
	for _, c := range candidates {
		p := filepath.Join(dir, c)
		if _, err := os.Stat(p); err == nil {
			workerBin, _ = filepath.Abs(p)
			break
		}
	}
	if workerBin == "" {
		// Try relative from CWD
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				workerBin, _ = filepath.Abs(c)
				break
			}
		}
	}
}

// ── Models ──────────────────────────────────────────────────────────

type APInfo struct {
	SSID     string `json:"ssid"`
	BSSID    string `json:"bssid"`
	Channel  int    `json:"channel"`
	Signal   int    `json:"signal"`
	Security string `json:"security"`
	Band     string `json:"band"`
	Vendor   string `json:"vendor"`
}

type ChannelInfo struct {
	Number      int     `json:"number"`
	Frequency   int     `json:"frequency_mhz"`
	Band        string  `json:"band"`
	RSSI        int     `json:"rssi"`
	Utilization float64 `json:"utilization"`
}

type ScanResponse struct {
	APs       []APInfo      `json:"aps"`
	Channels  []ChannelInfo `json:"channels"`
	Count     int           `json:"count"`
	Duration  string        `json:"duration"`
	Engine    string        `json:"engine"`
	Error     string        `json:"error"`
}

type StatusResponse struct {
	Version    string `json:"version"`
	Uptime     string `json:"uptime"`
	Worker     string `json:"worker"`
	WorkerOK   bool   `json:"worker_ok"`
	Interfaces []IfaceInfo `json:"interfaces"`
}

type IfaceInfo struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	Channel   int    `json:"channel"`
	Frequency int    `json:"frequency"`
	Signal    int    `json:"signal"`
	TxPower   int    `json:"txpower"`
	IsMonitor bool   `json:"is_monitor"`
}

type CrackResult struct {
	Found  bool   `json:"found"`
	Key    string `json:"key"`
	Tested int    `json:"tested"`
	Rate   string `json:"rate"`
	Error  string `json:"error"`
}

// ── Helpers ─────────────────────────────────────────────────────────

var startTime = time.Now()

func jsonResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func runWorker(args ...string) (string, error) {
	if workerBin == "" {
		return "", fmt.Errorf("hackit-worker binary not found")
	}
	cmd := exec.Command(workerBin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func findInterface() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "wlan0"
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "wl") {
			return name
		}
	}
	return "wlan0"
}

// ── Handlers ────────────────────────────────────────────────────────

// GET /api/health
func handleHealth(w http.ResponseWriter, r *http.Request) {
	workerOK := false
	if workerBin != "" {
		_, err := runWorker("status", findInterface())
		workerOK = err == nil
	}

	ifaces := []IfaceInfo{}
	entries, _ := os.ReadDir("/sys/class/net")
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "wl") || strings.HasPrefix(name, "eth") {
			ifaces = append(ifaces, IfaceInfo{Name: name})
		}
	}

	jsonResp(w, 200, StatusResponse{
		Version:    "1.0",
		Uptime:     time.Since(startTime).Round(time.Second).String(),
		Worker:     workerBin,
		WorkerOK:   workerOK,
		Interfaces: ifaces,
	})
}

// POST /api/scan
func handleScan(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	iface := r.URL.Query().Get("iface")
	if iface == "" {
		var body struct{ Iface string `json:"iface"` }
		json.NewDecoder(r.Body).Decode(&body)
		iface = body.Iface
	}
	if iface == "" {
		iface = findInterface()
	}

	resp := ScanResponse{Engine: "Go (nmcli)"}

	// Use nmcli for AP scan
	out, err := exec.Command("nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) < 10 {
				continue
			}
			ssid := parts[0]
			rawBSSID := strings.Join(parts[1:7], ":")
			bssid := strings.ReplaceAll(rawBSSID, "\\", "")
			signalStr := parts[7]
			channelStr := parts[8]
			security := strings.Join(parts[9:], ":")

			signal, _ := strconv.Atoi(signalStr)
			channel, _ := strconv.Atoi(channelStr)

			band := "2.4GHz"
			if channel > 13 {
				band = "5GHz"
			}

			resp.APs = append(resp.APs, APInfo{
				SSID:     ssid,
				BSSID:    bssid,
				Channel:  channel,
				Signal:   signal,
				Security: security,
				Band:     band,
			})
		}
	}

	resp.Count = len(resp.APs)
	resp.Duration = time.Since(start).Round(time.Millisecond).String()

	if resp.Count == 0 && err != nil {
		resp.Error = fmt.Sprintf("nmcli: %v", err)
	}

	jsonResp(w, 200, resp)
}

// POST /api/scan/deep — iw scan (requires root)
func handleDeepScan(w http.ResponseWriter, r *http.Request) {
	iface := findInterface()
	var body struct{ Iface string `json:"iface"` }
	json.NewDecoder(r.Body).Decode(&body)
	if body.Iface != "" {
		iface = body.Iface
	}

	resp := ScanResponse{Engine: "Go (iw)"}

	out, err := exec.Command("iw", "dev", iface, "scan").Output()
	if err != nil {
		resp.Error = fmt.Sprintf("iw scan: %v (try as root)", err)
		jsonResp(w, 200, resp)
		return
	}

	var current *APInfo
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BSS ") {
			if current != nil {
				resp.APs = append(resp.APs, *current)
			}
			parts := strings.Fields(line)
			bssid := ""
			if len(parts) >= 2 {
				bssid = strings.ToUpper(parts[1])
			}
			current = &APInfo{BSSID: bssid}
		} else if current != nil {
			if strings.Contains(line, "freq:") {
				freqStr := strings.Fields(line)
				if len(freqStr) >= 2 {
					freq, _ := strconv.Atoi(freqStr[1])
					current.Channel = freqToChannel(freq)
					current.Band = bandFromFreq(freq)
				}
			} else if strings.Contains(line, "signal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					signal, _ := strconv.Atoi(parts[1])
					current.Signal = signal
				}
			} else if strings.Contains(line, "SSID:") {
				ssid := strings.TrimPrefix(line, "SSID:")
				current.SSID = strings.TrimSpace(ssid)
			} else if strings.Contains(line, "WPA:") || strings.Contains(line, "RSN:") {
				if current.Security == "" {
					current.Security = "WPA"
				} else if !strings.Contains(current.Security, "WPA2") {
					current.Security += "+WPA2"
				}
			}
		}
	}
	if current != nil {
		resp.APs = append(resp.APs, *current)
	}
	resp.Count = len(resp.APs)
	jsonResp(w, 200, resp)
}

// POST /api/spectrum — Go dual-band scan
func handleSpectrum(w http.ResponseWriter, r *http.Request) {
	iface := findInterface()
	var body struct{ Iface string `json:"iface"` }
	json.NewDecoder(r.Body).Decode(&body)
	if body.Iface != "" {
		iface = body.Iface
	}

	channels := []ChannelInfo{}
	re := regexp.MustCompile(`Ch\s*(\d+)\s*\|\s*(\d+)\s*MHz\s*\|\s*(\S+)\s*\|\s*RSSI:\s*(-?\d+)`)

	out, err := runWorker("spectrum", iface)
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			m := re.FindStringSubmatch(line)
			if len(m) >= 5 {
				num, _ := strconv.Atoi(m[1])
				freq, _ := strconv.Atoi(m[2])
				rssi, _ := strconv.Atoi(m[4])
				channels = append(channels, ChannelInfo{
					Number:    num,
					Frequency: freq,
					Band:      m[3],
					RSSI:      rssi,
				})
			}
		}
	}

	jsonResp(w, 200, map[string]any{
		"channels": channels,
		"count":    len(channels),
		"raw":      out[:min(len(out), 2000)],
		"error":    "",
	})
}

// POST /api/interface/status
func handleIfaceStatus(w http.ResponseWriter, r *http.Request) {
	iface := findInterface()
	var body struct{ Iface string `json:"iface"` }
	json.NewDecoder(r.Body).Decode(&body)
	if body.Iface != "" {
		iface = body.Iface
	}

	info := IfaceInfo{Name: iface}

	// Try hackit-worker status
	out, err := runWorker("status", iface)
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			l := strings.TrimSpace(line)
			if strings.Contains(l, "MAC:") {
				info.MAC = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
			} else if strings.Contains(l, "channel:") {
				parts := strings.Fields(l)
				for i, p := range parts {
					if p == "channel:" && i+1 < len(parts) {
						info.Channel, _ = strconv.Atoi(parts[i+1])
					}
				}
			}
		}
	}

	// Read /sys for more info
	info = readSysInfo(iface, info)

	jsonResp(w, 200, map[string]any{
		"interface": info,
	})
}

// POST /api/interface/mode
func handleSetMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Iface string `json:"iface"`
		Mode  string `json:"mode"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Iface == "" {
		body.Iface = findInterface()
	}
	if body.Mode == "" {
		body.Mode = "monitor"
	}

	_, err := runWorker("mode", body.Iface, body.Mode)
	ok := err == nil

	jsonResp(w, 200, map[string]any{
		"ok":      ok,
		"message": fmt.Sprintf("%s → %s", body.Iface, body.Mode),
		"error":   errString(err),
	})
}

// POST /api/interface/channel
func handleSetChannel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Iface   string `json:"iface"`
		Channel int    `json:"channel"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Iface == "" {
		body.Iface = findInterface()
	}

	_, err := runWorker("channel", body.Iface, strconv.Itoa(body.Channel))
	ok := err == nil

	jsonResp(w, 200, map[string]any{
		"ok":      ok,
		"message": fmt.Sprintf("%s → ch %d", body.Iface, body.Channel),
		"error":   errString(err),
	})
}

// POST /api/interface/txpower
func handleSetTxPower(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Iface string `json:"iface"`
		Power int    `json:"power"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Iface == "" {
		body.Iface = findInterface()
	}

	_, err := runWorker("txpower", body.Iface, strconv.Itoa(body.Power))
	ok := err == nil

	jsonResp(w, 200, map[string]any{
		"ok":      ok,
		"message": fmt.Sprintf("%s → %ddBm", body.Iface, body.Power),
		"error":   errString(err),
	})
}

// POST /api/interface/mac
func handleSetMAC(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Iface  string `json:"iface"`
		Action string `json:"action"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Iface == "" {
		body.Iface = findInterface()
	}
	if body.Action == "" {
		body.Action = "random"
	}

	_, err := runWorker("mac", body.Iface, body.Action)
	ok := err == nil

	jsonResp(w, 200, map[string]any{
		"ok":      ok,
		"message": fmt.Sprintf("%s MAC %s", body.Iface, body.Action),
		"error":   errString(err),
	})
}

// POST /api/crack — WPA cracking via hackit-worker
func handleCrack(w http.ResponseWriter, r *http.Request) {
	var body struct {
		HashFile string `json:"hashfile"`
		Wordlist string `json:"wordlist"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	result := CrackResult{}
	out, err := runWorker("crack", body.HashFile, body.Wordlist)
	if err != nil {
		result.Error = err.Error()
		jsonResp(w, 200, result)
		return
	}
	result.Tested = 0

	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		m := regexp.MustCompile(`Tested\s+([\d,]+)\s*/\s*[\d,]+\s*\(([\d.]+)\s*ps\)`).FindStringSubmatch(l)
		if len(m) >= 3 {
			tested, _ := strconv.Atoi(strings.ReplaceAll(m[1], ",", ""))
			result.Tested = tested
			result.Rate = m[2]
		}
		if strings.Contains(l, "KEY FOUND:") {
			result.Found = true
			result.Key = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
		}
	}

	jsonResp(w, 200, result)
}

// POST /api/packet-gen
func handlePacketGen(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Iface     string `json:"iface"`
		FrameType string `json:"frame_type"`
		SSID      string `json:"ssid"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Iface == "" {
		body.Iface = findInterface()
	}
	if body.FrameType == "" {
		body.FrameType = "auth"
	}
	if body.SSID == "" {
		body.SSID = "HackIT"
	}

	_, err := runWorker("packet-gen", body.Iface, body.FrameType, body.SSID)
	jsonResp(w, 200, map[string]any{
		"ok":    err == nil,
		"error": errString(err),
	})
}

// POST /api/wps-pin
func handleWPSPin(w http.ResponseWriter, r *http.Request) {
	var body struct{ BSSID string `json:"bssid"` }
	json.NewDecoder(r.Body).Decode(&body)

	pin := ""
	candidates := []string{}
	out, err := runWorker("wps-pin", body.BSSID)
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "PIN:") || strings.HasPrefix(l, "WPS PIN:") {
				pin = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
			} else if strings.Contains(l, "Candidates:") {
				parts := strings.SplitN(l, ":", 2)
				if len(parts) == 2 {
					for _, c := range strings.Split(parts[1], ",") {
						c = strings.TrimSpace(c)
						if c != "" {
							candidates = append(candidates, c)
						}
					}
				}
			}
		}
	}

	jsonResp(w, 200, map[string]any{
		"pin":        pin,
		"candidates": candidates,
		"error":      errString(err),
	})
}

// ── Utility ─────────────────────────────────────────────────────────

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func freqToChannel(freq int) int {
	if freq >= 2412 && freq <= 2484 {
		return (freq - 2412) / 5 + 1
	}
	if freq >= 5180 && freq <= 5885 {
		return (freq - 5180) / 5 + 36
	}
	return 0
}

func bandFromFreq(freq int) string {
	if freq >= 2412 && freq <= 2484 {
		return "2.4GHz"
	}
	if freq >= 5180 && freq <= 5885 {
		return "5GHz"
	}
	return "?"
}

func readSysInfo(iface string, info IfaceInfo) IfaceInfo {
	base := "/sys/class/net/" + iface

	// MAC
	if data, err := os.ReadFile(base + "/address"); err == nil {
		info.MAC = strings.TrimSpace(string(data))
	}

	// Wireless info
	wirelessBase := base + "/wireless"
	if _, err := os.Stat(wirelessBase); err == nil {
		if data, err := os.ReadFile(wirelessBase + "/channel"); err == nil {
			info.Channel, _ = strconv.Atoi(strings.TrimSpace(string(data)))
		}
	}

	return info
}

// ── CORS Middleware ─────────────────────────────────────────────────

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Main ────────────────────────────────────────────────────────────

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/scan", handleScan)
	mux.HandleFunc("/api/scan/deep", handleDeepScan)
	mux.HandleFunc("/api/spectrum", handleSpectrum)
	mux.HandleFunc("/api/interface/status", handleIfaceStatus)
	mux.HandleFunc("/api/interface/mode", handleSetMode)
	mux.HandleFunc("/api/interface/channel", handleSetChannel)
	mux.HandleFunc("/api/interface/txpower", handleSetTxPower)
	mux.HandleFunc("/api/interface/mac", handleSetMAC)
	mux.HandleFunc("/api/crack", handleCrack)
	mux.HandleFunc("/api/packet-gen", handlePacketGen)
	mux.HandleFunc("/api/wps-pin", handleWPSPin)

	addr := "127.0.0.1:" + port
	log.Printf("[GO-WEB] Starting Go web server on %s", addr)
	log.Printf("[GO-WEB] Worker binary: %s", workerBin)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[GO-WEB] Failed to listen: %v", err)
	}

	log.Printf("[GO-WEB] Ready — try: curl http://127.0.0.1:%s/api/health", port)

	// Print available endpoints to stderr
	log.Println("[GO-WEB] Endpoints:")
	log.Println("  GET  /api/health           — server + worker health")
	log.Println("  POST /api/scan             — AP scan (nmcli)")
	log.Println("  POST /api/scan/deep        — deep scan (iw, needs root)")
	log.Println("  POST /api/spectrum         — spectrum analysis")
	log.Println("  POST /api/interface/status — interface status")
	log.Println("  POST /api/interface/mode   — set monitor/managed")
	log.Println("  POST /api/interface/channel— set channel")
	log.Println("  POST /api/interface/txpower— set TX power")
	log.Println("  POST /api/interface/mac    — change MAC")
	log.Println("  POST /api/crack            — WPA crack")
	log.Println("  POST /api/packet-gen       — inject 802.11 frames")
	log.Println("  POST /api/wps-pin          — compute WPS PIN")

	if err := http.Serve(listener, cors(mux)); err != nil {
		log.Fatalf("[GO-WEB] Server error: %v", err)
	}
}
