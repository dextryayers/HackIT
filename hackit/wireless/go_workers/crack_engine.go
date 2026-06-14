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

type CrackEngine struct {
	Running     bool
	Progress    float64
	Total       int64
	Tested      int64
	Found       bool
	Password    string
	StartTime   time.Time
	StopChan    chan struct{}
	mu          sync.Mutex
	HashcatPath string
}

func NewCrackEngine() *CrackEngine {
	return &CrackEngine{
		StopChan: make(chan struct{}),
	}
}

func (c *CrackEngine) CrackWPA(hashfile, wordlist, rules string) error {
	c.mu.Lock()
	c.Running = true
	c.StartTime = time.Now()
	c.Progress = 0
	c.Tested = 0
	c.Found = false
	c.Total = 0
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.Running = false
		c.mu.Unlock()
	}()

	fmt.Printf("[GO-CRACK] WPA cracking: %s <- %s [rules: %s]\n", hashfile, wordlist, rules)

	if _, err := os.Stat(hashfile); os.IsNotExist(err) {
		return fmt.Errorf("hash file not found: %s", hashfile)
	}
	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		return fmt.Errorf("wordlist not found: %s", wordlist)
	}

	c.Total = countLines(wordlist)
	fmt.Printf("[GO-CRACK] Wordlist contains %d passwords\n", c.Total)

	if c.HashcatPath != "" {
		return c.crackWithHashcat(hashfile, wordlist, rules, "22000")
	}

	return c.crackNative(hashfile, wordlist)
}

func (c *CrackEngine) CrackPMKID(hashfile, wordlist string) error {
	c.mu.Lock()
	c.Running = true
	c.StartTime = time.Now()
	c.Progress = 0
	c.Tested = 0
	c.Found = false
	c.Total = 0
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.Running = false
		c.mu.Unlock()
	}()

	fmt.Printf("[GO-CRACK] PMKID cracking: %s <- %s\n", hashfile, wordlist)

	if _, err := os.Stat(hashfile); os.IsNotExist(err) {
		return fmt.Errorf("hash file not found: %s", hashfile)
	}
	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		return fmt.Errorf("wordlist not found: %s", wordlist)
	}

	if c.HashcatPath != "" {
		return c.crackWithHashcat(hashfile, wordlist, "", "16800")
	}

	return c.crackNative(hashfile, wordlist)
}

func (c *CrackEngine) crackWithHashcat(hashfile, wordlist, rules, mode string) error {
	args := []string{"-m", mode, "-a", "0", hashfile, wordlist, "--status", "--status-timer=1", "-o", "found.txt", "--potfile-disable"}

	if rules != "" {
		args = append(args, "-r", rules)
	}

	cmd := exec.Command(c.HashcatPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("hashcat stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("hashcat start: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-c.StopChan:
			cmd.Process.Kill()
			fmt.Println("[GO-CRACK] Hashcat stopped")
			return nil
		default:
		}

		line := scanner.Text()
		c.parseHashcatStatus(line)

		if strings.Contains(line, "Cracked.") || strings.Contains(line, "Recovered") {
			c.mu.Lock()
			c.Found = true
			c.mu.Unlock()
		}
	}

	return cmd.Wait()
}

func (c *CrackEngine) parseHashcatStatus(line string) {
	if strings.HasPrefix(line, "STATUS") {
		parts := strings.Split(line, "\t")
		if len(parts) >= 4 {
			tested, _ := strconv.ParseInt(parts[2], 10, 64)
			total, _ := strconv.ParseInt(parts[3], 10, 64)
			c.mu.Lock()
			c.Tested = tested
			c.Total = total
			if total > 0 {
				c.Progress = float64(tested) / float64(total) * 100.0
			}
			c.mu.Unlock()
		}
	}
}

func (c *CrackEngine) crackNative(hashfile, wordlist string) error {
	hashFile, err := os.Open(hashfile)
	if err != nil {
		return err
	}
	defer hashFile.Close()

	scanner := bufio.NewScanner(hashFile)
	var hashLine string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			hashLine = line
			break
		}
	}

	if hashLine == "" {
		return fmt.Errorf("no valid hash in %s", hashfile)
	}

	pmkidHex, apMac, clientMac, ssid, err := ParseHC22000Line(hashLine)
	if err != nil {
		return fmt.Errorf("parse hash failed: %w", err)
	}

	targetPMKID, _ := hexStringToBytes(pmkidHex)

	wordFile, err := os.Open(wordlist)
	if err != nil {
		return err
	}
	defer wordFile.Close()

	wordScanner := bufio.NewScanner(wordFile)
	wordScanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	start := time.Now()

	for wordScanner.Scan() {
		select {
		case <-c.StopChan:
			fmt.Println("[GO-CRACK] Crack stopped")
			return nil
		default:
		}

		password := strings.TrimSpace(wordScanner.Text())
		if password == "" {
			continue
		}

		c.mu.Lock()
		c.Tested++
		c.Progress = float64(c.Tested) / float64(c.Total) * 100.0
		c.mu.Unlock()

		if c.Tested%5000 == 0 {
			elapsed := time.Since(start).Seconds()
			rate := float64(c.Tested) / elapsed
			fmt.Printf("[GO-CRACK] %d/%d (%.1f%%) | %.0f p/s\n", c.Tested, c.Total, c.Progress, rate)
		}

		pmk := DerivePMK(password, ssid)
		pmkid := ComputePMKID(pmk, apMac, clientMac)

		if hmacEqual(pmkid, targetPMKID) {
			c.mu.Lock()
			c.Found = true
			c.Password = password
			c.Running = false
			c.mu.Unlock()

			fmt.Printf("[GO-CRACK] PASSWORD FOUND: %s\n", password)
			return nil
		}
	}

	fmt.Println("[GO-CRACK] Password not found in wordlist")
	return nil
}

func (c *CrackEngine) DetectGPU() map[string]interface{} {
	result := map[string]interface{}{
		"gpu":      false,
		"opencl":   false,
		"cuda":     false,
		"devices":  []string{},
		"hashcat":  false,
	}

	if c.HashcatPath != "" {
		result["hashcat"] = true
	}

	if runtime.GOOS == "linux" {
		if out, err := exec.Command("sh", "-c", "lspci 2>/dev/null | grep -iE 'vga|3d|display'").CombinedOutput(); err == nil {
			lines := strings.Split(string(out), "\n")
			var devices []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					devices = append(devices, line)
				}
			}
			result["devices"] = devices
		}

		if _, err := exec.Command("sh", "-c", "which nvidia-smi 2>/dev/null").CombinedOutput(); err == nil {
			result["cuda"] = true
			result["gpu"] = true
		}

		if _, err := exec.Command("sh", "-c", "which clinfo 2>/dev/null").CombinedOutput(); err == nil {
			result["opencl"] = true
			result["gpu"] = true
		}

		if out, err := exec.Command("sh", "-c", "nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader 2>/dev/null").CombinedOutput(); err == nil {
			result["nvidia"] = strings.TrimSpace(string(out))
		}
	}

	fmt.Printf("[GO-CRACK] GPU detection: %+v\n", result)
	return result
}

func (c *CrackEngine) GetProgress() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Progress
}

func (c *CrackEngine) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Running {
		close(c.StopChan)
		c.StopChan = make(chan struct{})
		if c.HashcatPath != "" {
			exec.Command("sh", "-c", "killall hashcat 2>/dev/null").Run()
		}
		fmt.Println("[GO-CRACK] Crack stopped")
	}
}

func (c *CrackEngine) PrintJSON() {
	c.mu.Lock()
	defer c.mu.Unlock()

	elapsed := time.Since(c.StartTime).Seconds()
	rate := float64(0)
	if elapsed > 0 {
		rate = float64(c.Tested) / elapsed
	}

	data := map[string]interface{}{
		"running":  c.Running,
		"progress": c.Progress,
		"tested":   c.Tested,
		"total":    c.Total,
		"found":    c.Found,
		"password": c.Password,
		"elapsed":  elapsed,
		"rate":     rate,
	}

	out, _ := json.Marshal(data)
	fmt.Println(string(out))
}

func countLines(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	var count int64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
	}
	return count
}

var _ = strconv.FormatInt
