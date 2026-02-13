package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Reporter handles real-time output of scan results
type Reporter struct {
	mu            sync.Mutex
	resultsBuffer []PortResult
}

// ReportResult prints a single port result as JSON to stdout
func (r *Reporter) ReportResult(res PortResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Buffer the result for final sorted output
	r.resultsBuffer = append(r.resultsBuffer, res)

	// Real-time notification for open ports (unsorted for speed)
	if res.State == "open" {
		serviceName := strings.ToUpper(res.Service)
		info := res.Version
		if info == "" && res.Banner != "" {
			info = res.Banner
			if idx := strings.Index(info, "\n"); idx != -1 {
				info = info[:idx]
			}
			if len(info) > 50 {
				info = info[:47] + "..."
			}
		}
		if info != "" {
			info = " | " + strings.TrimSpace(info)
		}
		fmt.Printf("[+] Real Open: %-5d %-15s%s\n", res.Port, serviceName, info)
	}

	data, _ := json.Marshal(res)
	fmt.Printf("RESULT:%s\n", string(data))
}

// PrintFinalTable displays the final sorted results table nmap-style
func (r *Reporter) PrintFinalTable() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.resultsBuffer) == 0 {
		return
	}

	// Sort results by port number (ascending)
	sort.Slice(r.resultsBuffer, func(i, j int) bool {
		return r.resultsBuffer[i].Port < r.resultsBuffer[j].Port
	})

	fmt.Println("\nPORT      STATE    SERVICE         VERSION / BANNER")
	fmt.Println("--------- -------- --------------- -----------------------")

	for _, res := range r.resultsBuffer {
		// Skip filtered/closed if not requested (optional logic, but here we show all discovered)
		state := res.State
		if state == "" {
			state = "unknown"
		}

		// Normalize service name to UPPERCASE for consistency
		serviceName := strings.ToUpper(res.Service)

		info := res.Version
		if info == "" && res.Banner != "" {
			info = res.Banner
			if idx := strings.Index(info, "\n"); idx != -1 {
				info = info[:idx]
			}
			if len(info) > 40 {
				info = info[:37] + "..."
			}
		}

		fmt.Printf("%-9s %-8s %-15s %s\n",
			fmt.Sprintf("%d/tcp", res.Port),
			state,
			serviceName,
			strings.TrimSpace(info),
		)
	}
	fmt.Println()
}

// ReportStatus prints a status message as JSON
func (r *Reporter) ReportStatus(status string, progress float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	msg := map[string]interface{}{
		"type":     "status",
		"message":  status,
		"progress": progress,
	}
	data, _ := json.Marshal(msg)
	fmt.Printf("STATUS:%s\n", string(data))
}

// ReportError prints an error message as JSON
func (r *Reporter) ReportError(err string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	msg := map[string]interface{}{
		"type":  "error",
		"error": err,
	}
	data, _ := json.Marshal(msg)
	fmt.Printf("ERROR:%s\n", string(data))
}
