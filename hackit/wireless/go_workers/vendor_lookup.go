package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// OUITable manages live OUI resolution using IEEE data
type OUITable struct {
	mu      sync.RWMutex
	vendors map[string]string
	ready   bool
}

var GlobalOUI = &OUITable{
	vendors: make(map[string]string),
	ready:   false,
}

func (o *OUITable) EnsureDatabase() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.ready && len(o.vendors) > 0 {
		return nil
	}

	dbPath := filepath.Join(os.TempDir(), "hackit_oui_mac.txt")
	info, err := os.Stat(dbPath)
	if os.IsNotExist(err) || info.Size() < 100000 {
		fmt.Println("[GO-WORKER] Reaching out to IEEE database to download latest OUI table...")
		resp, err := http.Get("https://standards-oui.ieee.org/oui/oui.txt")
		if err != nil {
			return fmt.Errorf("failed to download IEEE OUI: %v", err)
		}
		defer resp.Body.Close()

		out, err := os.Create(dbPath)
		if err != nil {
			return err
		}
		defer out.Close()
		_, _ = io.Copy(out, resp.Body)
		fmt.Println("[GO-WORKER] IEEE Database synced to temp directory.")
	}

	file, err := os.Open(dbPath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "(hex)") {
			parts := strings.SplitN(line, "(hex)", 2)
			if len(parts) == 2 {
				macPrefix := strings.ReplaceAll(strings.TrimSpace(parts[0]), "-", ":")
				vendorName := strings.TrimSpace(parts[1])
				o.vendors[strings.ToUpper(macPrefix)] = vendorName
			}
		}
	}
	o.ready = true
	return nil
}

// LookupVendor returns the manufacturer of a MAC address natively
func (o *OUITable) LookupVendor(mac string) string {
	_ = o.EnsureDatabase()
	o.mu.RLock()
	defer o.mu.RUnlock()

	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	if len(mac) >= 8 {
		prefix := mac[:8]
		if vendor, exists := o.vendors[prefix]; exists {
			return vendor
		}
	}
	return "UNKNOWN_VENDOR"
}
