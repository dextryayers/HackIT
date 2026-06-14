package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AggressiveScanner struct {
	Interface string
	Results   []ScanResult
	mu        sync.Mutex
}

type ScanResult struct {
	BSSID   string  `json:"bssid"`
	SSID    string  `json:"ssid"`
	Channel int     `json:"channel"`
	Freq    int     `json:"freq"`
	Band    string  `json:"band"`
	RSSI    int     `json:"rssi"`
	Noise   int     `json:"noise"`
	Util    float64 `json:"utilization"`
	Hidden  bool    `json:"hidden"`
	Encrypt string  `json:"encryption"`
}

func NewAggressiveScanner(iface string) *AggressiveScanner {
	return &AggressiveScanner{Interface: iface}
}

func (a *AggressiveScanner) ScanAllBands() []ScanResult {
	a.mu.Lock()
	defer a.mu.Unlock()

	fmt.Printf("[GO-SCAN] Aggressive dual-band scan on %s...\n", a.Interface)

	var wg sync.WaitGroup
	resultChan := make(chan []ScanResult, 3)

	bands := []string{"2.4GHz", "5GHz", "6GHz"}
	for _, band := range bands {
		wg.Add(1)
		go func(b string) {
			defer wg.Done()
			res := a.scanBand(b)
			resultChan <- res
		}(band)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var all []ScanResult
	for res := range resultChan {
		all = append(all, res...)
	}

	a.Results = all
	fmt.Printf("[GO-SCAN] Found %d APs across all bands\n", len(all))
	return all
}

func (a *AggressiveScanner) scanBand(band string) []ScanResult {
	var results []ScanResult

	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return results
	}

	var channels []int
	switch band {
	case "2.4GHz":
		channels = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	case "5GHz":
		channels = []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}
	case "6GHz":
		channels = []int{1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233}
	}

	cmdStr := fmt.Sprintf("iw dev %s scan 2>/dev/null", a.Interface)
	output, err := exec.Command("sh", "-c", cmdStr).CombinedOutput()
	if err == nil {
		results = a.parseIwOutput(string(output), band)
	}

	if len(results) == 0 && runtime.GOOS == "linux" {
		if out, err := exec.Command("nmcli", "-f", "BSSID,CHAN,FREQ,SIGNAL,SSID,SECURITY", "dev", "wifi", "list", "--rescan", "yes").CombinedOutput(); err == nil {
			results = a.parseNmcliOutput(string(out), band)
		}
		if len(results) == 0 {
			results = a.scanWithIwlist(channels, band)
		}
	}

	return results
}

func (a *AggressiveScanner) parseIwOutput(output string, band string) []ScanResult {
	var results []ScanResult
	scanner := bufio.NewScanner(strings.NewReader(output))
	var current ScanResult
	var inBSS bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "BSS ") {
			if inBSS && current.BSSID != "" {
				if matchesBand(current.Freq, band) {
					results = append(results, current)
				}
			}
			parts := strings.Fields(line)
			if len(parts) > 1 {
				current = ScanResult{BSSID: parts[1]}
				inBSS = true
			}
		} else if inBSS {
			if strings.HasPrefix(line, "freq:") {
				f, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "freq:")))
				current.Freq = f
				current.Band = freqToBand(f)
				current.Channel = freqToChannel(f)
			} else if strings.HasPrefix(line, "signal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					s := strings.TrimSuffix(parts[1], ".00")
					s = strings.TrimSuffix(s, " dBm")
					current.RSSI, _ = strconv.Atoi(s)
				}
			} else if strings.HasPrefix(line, "SSID:") {
				ssid := strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
				if ssid == "" || ssid == "\x00" {
					current.Hidden = true
				} else {
					current.SSID = ssid
				}
			} else if strings.Contains(line, "Group cipher") || strings.Contains(line, "Pairwise cipher") {
				if strings.Contains(line, "CCMP") || strings.Contains(line, "TKIP") {
					current.Encrypt = "WPA2"
				}
			}
		}
	}

	if inBSS && current.BSSID != "" && matchesBand(current.Freq, band) {
		results = append(results, current)
	}

	return results
}

func (a *AggressiveScanner) parseNmcliOutput(output string, band string) []ScanResult {
	var results []ScanResult
	scanner := bufio.NewScanner(strings.NewReader(output))
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if first {
			first = false
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			r := ScanResult{}
			r.BSSID = fields[0]
			r.Channel, _ = strconv.Atoi(fields[1])
			r.Freq, _ = strconv.Atoi(fields[2])
			sig, _ := strconv.Atoi(fields[3])
			r.RSSI = sig/2 - 100
			r.SSID = fields[4]
			r.Band = freqToBand(r.Freq)
			r.Encrypt = fields[5]
			if matchesBand(r.Freq, band) {
				results = append(results, r)
			}
		}
	}
	return results
}

func (a *AggressiveScanner) scanWithIwlist(channels []int, band string) []ScanResult {
	var results []ScanResult
	for _, ch := range channels {
		exec.Command("sh", "-c", fmt.Sprintf("iw dev %s set channel %d 2>/dev/null", a.Interface, ch)).Run()
		time.Sleep(20 * time.Millisecond)
		out, err := exec.Command("sh", "-c", fmt.Sprintf("iwlist %s scan 2>/dev/null", a.Interface)).CombinedOutput()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		var current ScanResult
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "Cell") {
				if current.BSSID != "" {
					results = append(results, current)
				}
				current = ScanResult{Channel: ch, Band: band}
			} else if strings.Contains(line, "Address:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					current.BSSID = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(line, "ESSID:") {
				ssid := strings.TrimSpace(strings.TrimPrefix(line, "ESSID:"))
				ssid = strings.Trim(ssid, "\"")
				if ssid == "" {
					current.Hidden = true
				} else {
					current.SSID = ssid
				}
			} else if strings.Contains(line, "Signal level") {
				parts := strings.Fields(line)
				for _, p := range parts {
					if v, err := strconv.Atoi(strings.TrimSuffix(p, " dBm")); err == nil {
						current.RSSI = v
					}
				}
			} else if strings.Contains(line, "Encryption key:") {
				if strings.Contains(line, "on") {
					current.Encrypt = "WPA"
				}
			}
		}
		if current.BSSID != "" {
			results = append(results, current)
		}
	}
	return results
}

func (a *AggressiveScanner) ScanHiddenSSIDs() []ScanResult {
	fmt.Printf("[GO-SCAN] Probing for hidden SSIDs on %s...\n", a.Interface)
	var hidden []ScanResult

	if runtime.GOOS != "linux" {
		return hidden
	}

	probeSsids := []string{"", "\x00", " ", "a", "test", "wireless"}
	for _, probe := range probeSsids {
		exec.Command("sh", "-c", fmt.Sprintf("iw dev %s scan probe-ssid %s 2>/dev/null", a.Interface, probe)).Run()
		time.Sleep(50 * time.Millisecond)
	}

	out, err := exec.Command("sh", "-c", fmt.Sprintf("iw dev %s scan 2>/dev/null", a.Interface)).CombinedOutput()
	if err != nil {
		return hidden
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var current ScanResult
	inBSS := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "BSS ") {
			if inBSS && current.BSSID != "" && current.Hidden {
				hidden = append(hidden, current)
			}
			parts := strings.Fields(line)
			if len(parts) > 1 {
				current = ScanResult{BSSID: parts[1], Hidden: true}
				inBSS = true
			}
		} else if inBSS {
			if strings.HasPrefix(line, "SSID:") {
				ssid := strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
				if ssid != "" && ssid != "\x00" {
					current.SSID = ssid
					current.Hidden = false
				}
			} else if strings.HasPrefix(line, "freq:") {
				f, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "freq:")))
				current.Freq = f
				current.Band = freqToBand(f)
				current.Channel = freqToChannel(f)
			} else if strings.HasPrefix(line, "signal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					current.RSSI, _ = strconv.Atoi(strings.TrimSuffix(parts[1], " dBm"))
				}
			}
		}
	}
	if inBSS && current.BSSID != "" && current.Hidden {
		hidden = append(hidden, current)
	}

	fmt.Printf("[GO-SCAN] Found %d hidden SSIDs\n", len(hidden))
	return hidden
}

func (a *AggressiveScanner) MeasureChannelUtil(channel int) float64 {
	if runtime.GOOS != "linux" {
		return 0.0
	}

	freq := channelToFreq(channel)
	if freq == 0 {
		return 0.0
	}

	exec.Command("sh", "-c", fmt.Sprintf("iw dev %s set channel %d 2>/dev/null", a.Interface, channel)).Run()
	time.Sleep(100 * time.Millisecond)

	out, err := exec.Command("sh", "-c", fmt.Sprintf("iw dev %s survey dump 2>/dev/null | grep -A 5 'in use'", a.Interface)).CombinedOutput()
	if err != nil {
		return 0.0
	}

	var busy, total uint64
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "channel busy time") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				busy, _ = strconv.ParseUint(parts[3], 10, 64)
			}
		} else if strings.HasPrefix(line, "channel time") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				total, _ = strconv.ParseUint(parts[2], 10, 64)
			}
		}
	}

	if total == 0 {
		return 0.0
	}

	return float64(busy) / float64(total) * 100.0
}

func (a *AggressiveScanner) PrintJSON() {
	a.mu.Lock()
	defer a.mu.Unlock()

	data := map[string]interface{}{
		"interface": a.Interface,
		"count":     len(a.Results),
		"results":   a.Results,
	}

	out, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("[GO-ERROR] JSON marshal failed: %v\n", err)
		return
	}
	fmt.Println(string(out))
}

func freqToBand(freq int) string {
	if freq >= 2400 && freq <= 2500 {
		return "2.4GHz"
	} else if freq >= 5000 && freq <= 5900 {
		return "5GHz"
	} else if freq >= 5925 && freq <= 7125 {
		return "6GHz"
	}
	return "Unknown"
}

func freqToChannel(freq int) int {
	if freq >= 2412 && freq <= 2484 {
		if freq == 2484 {
			return 14
		}
		return (freq - 2407) / 5
	} else if freq >= 5035 && freq <= 5825 {
		return (freq - 5000) / 5
	} else if freq >= 5955 && freq <= 7115 {
		return (freq - 5950) / 5
	}
	return 0
}

func channelToFreq(ch int) int {
	if ch >= 1 && ch <= 14 {
		return 2407 + (ch * 5)
	} else if ch >= 36 && ch <= 165 {
		return 5000 + (ch * 5)
	} else if ch >= 1 && ch <= 233 {
		return 5950 + (ch * 5)
	}
	return 0
}

func matchesBand(freq int, band string) bool {
	return freqToBand(freq) == band
}
