package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TargetSpec represents target specification
type TargetSpec struct {
	Targets     []string
	Exclude     []string
	Randomize   bool
	IPv6        bool
	ResolvedIPs []string
}

// NewTargetSpec creates a new target specification
func NewTargetSpec() *TargetSpec {
	return &TargetSpec{
		Targets:     []string{},
		Exclude:     []string{},
		Randomize:   false,
		IPv6:        false,
		ResolvedIPs: []string{},
	}
}

// ParseTargets parses various target formats
func (ts *TargetSpec) ParseTargets(input string) error {
	// Check if it's a file
	if strings.HasPrefix(input, "@") {
		filename := strings.TrimPrefix(input, "@")
		return ts.loadTargetsFromFile(filename)
	}

	// Parse as CIDR, range, or single target
	targets, err := ts.parseTargetString(input)
	if err != nil {
		return err
	}

	ts.Targets = append(ts.Targets, targets...)
	return nil
}

// parseTargetString parses a single target string
func (ts *TargetSpec) parseTargetString(input string) ([]string, error) {
	var targets []string

	// Check for CIDR notation
	if strings.Contains(input, "/") {
		ips, err := ts.expandCIDR(input)
		if err != nil {
			return nil, err
		}
		targets = append(targets, ips...)
	} else if strings.Contains(input, "-") {
		// Check for IP range
		ips, err := ts.expandIPRange(input)
		if err != nil {
			return nil, err
		}
		targets = append(targets, ips...)
	} else {
		// Single target
		targets = append(targets, input)
	}

	return targets, nil
}

// expandCIDR expands a CIDR notation to individual IPs
func (ts *TargetSpec) expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
		if len(ips) >= 65536 { // Limit to prevent memory issues
			break
		}
	}

	return ips, nil
}

// expandIPRange expands an IP range (e.g., 192.168.1.1-192.168.1.100)
func (ts *TargetSpec) expandIPRange(rangeStr string) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format: %s", rangeStr)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP addresses in range")
	}

	var ips []string
	for ip := startIP; ip.String() != endIP.String(); {
		ips = append(ips, ip.String())
		if len(ips) >= 65536 { // Limit to prevent memory issues
			break
		}
		// Increment IP
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}

	return ips, nil
}

// loadTargetsFromFile loads targets from a file
func (ts *TargetSpec) loadTargetsFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		targets, err := ts.parseTargetString(line)
		if err != nil {
			return err
		}

		ts.Targets = append(ts.Targets, targets...)
	}

	return scanner.Err()
}

// ResolveTargets resolves all targets to IP addresses
func (ts *TargetSpec) ResolveTargets() error {
	for _, target := range ts.Targets {
		// If it's already an IP, add it directly
		if net.ParseIP(target) != nil {
			ts.ResolvedIPs = append(ts.ResolvedIPs, target)
			continue
		}

		// Resolve hostname to IP
		ips, err := net.LookupIP(target)
		if err != nil {
			return fmt.Errorf("failed to resolve %s: %w", target, err)
		}

		for _, ip := range ips {
			ts.ResolvedIPs = append(ts.ResolvedIPs, ip.String())
		}
	}

	// Apply exclusions
	ts.applyExclusions()

	// Randomize if requested
	if ts.Randomize {
		ts.randomizeTargets()
	}

	return nil
}

// applyExclusions removes excluded targets
func (ts *TargetSpec) applyExclusions() {
	if len(ts.Exclude) == 0 {
		return
	}

	excludeMap := make(map[string]bool)
	for _, excl := range ts.Exclude {
		excludeMap[excl] = true
	}

	filtered := []string{}
	for _, ip := range ts.ResolvedIPs {
		if !excludeMap[ip] {
			filtered = append(filtered, ip)
		}
	}

	ts.ResolvedIPs = filtered
}

// randomizeTargets randomizes the target order
func (ts *TargetSpec) randomizeTargets() {
	rand.Seed(time.Now().UnixNano())
	for i := len(ts.ResolvedIPs) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		ts.ResolvedIPs[i], ts.ResolvedIPs[j] = ts.ResolvedIPs[j], ts.ResolvedIPs[i]
	}
}

// GetTargets returns all resolved target IPs
func (ts *TargetSpec) GetTargets() []string {
	return ts.ResolvedIPs
}

// PortRange represents a port range specification
type PortRange struct {
	Start int
	End   int
}

// ParsePortRange parses port range specification
func ParsePortRange(portStr string) ([]int, error) {
	var ports []int

	// Handle comma-separated ports and ranges
	ranges := strings.Split(portStr, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)

		if strings.Contains(r, "-") {
			// Range like 1-100
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", r)
			}

			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", parts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", parts[1])
			}

			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}

			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			// Single port
			port, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", r)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}

			ports = append(ports, port)
		}
	}

	// Sort and deduplicate
	sort.Ints(ports)
	unique := []int{}
	prev := -1
	for _, p := range ports {
		if p != prev {
			unique = append(unique, p)
			prev = p
		}
	}

	return unique, nil
}

// GetCommonPorts returns common ports for quick scanning
func GetCommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
		993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 9200,
	}
}

// GetTopPorts returns top N common ports
func GetTopPorts(n int) []int {
	topPorts := []int{
		80, 23, 443, 21, 22, 25, 53, 110, 995, 993, 135, 139, 143,
		445, 3306, 3389, 1723, 5900, 8080, 8443, 9200, 5432, 6379, 27017,
	}

	if n <= 0 || n > len(topPorts) {
		return topPorts
	}

	return topPorts[:n]
}

// ValidateTarget validates a target specification
func ValidateTarget(target string) error {
	// Check if it's a file
	if strings.HasPrefix(target, "@") {
		filename := strings.TrimPrefix(target, "@")
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			return fmt.Errorf("target file not found: %s", filename)
		}
		return nil
	}

	// Check for CIDR
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		return err
	}

	// Check for IP range
	if strings.Contains(target, "-") {
		parts := strings.Split(target, "-")
		if len(parts) != 2 {
			return fmt.Errorf("invalid target format: %s", target)
		}

		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		endIP := net.ParseIP(strings.TrimSpace(parts[1]))

		if startIP == nil || endIP == nil {
			return fmt.Errorf("invalid IP addresses in range")
		}

		return nil
	}

	// Check for hostname or IP
	if net.ParseIP(target) != nil {
		return nil
	}

	// Validate hostname format
	hostnameRegex := regexp.MustCompile(`^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`)
	if !hostnameRegex.MatchString(target) {
		return fmt.Errorf("invalid hostname: %s", target)
	}

	return nil
}

// ParseTargetList parses a list of targets
func ParseTargetList(targets []string) (*TargetSpec, error) {
	spec := NewTargetSpec()

	for _, target := range targets {
		if err := spec.ParseTargets(target); err != nil {
			return nil, err
		}
	}

	if err := spec.ResolveTargets(); err != nil {
		return nil, err
	}

	return spec, nil
}

// TargetStats represents target statistics
type TargetStats struct {
	TotalTargets  int
	TotalPorts    int
	EstimatedTime time.Duration
}

// CalculateScanStats calculates scan statistics
func CalculateScanStats(targets []string, ports []int, timing int) TargetStats {
	stats := TargetStats{
		TotalTargets: len(targets),
		TotalPorts:   len(ports),
	}

	// Estimate scan time based on timing template
	timeMultiplier := float64(1)
	switch timing {
	case 0: // Paranoid
		timeMultiplier = 100
	case 1: // Sneaky
		timeMultiplier = 50
	case 2: // Polite
		timeMultiplier = 10
	case 3: // Normal
		timeMultiplier = 1
	case 4: // Aggressive
		timeMultiplier = 0.5
	case 5: // Insane
		timeMultiplier = 0.25
	}

	// Rough estimation: 1ms per port per target
	totalProbes := len(targets) * len(ports)
	estimatedDuration := time.Duration(float64(totalProbes) * float64(time.Millisecond) * timeMultiplier)
	stats.EstimatedTime = estimatedDuration

	return stats
}

// incrementIP increments an IP address (local helper function)
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// TargetValidator validates target specifications
type TargetValidator struct {
	AllowedCIDRs []string
	AllowedIPs   []string
	BlockedIPs   []string
}

// NewTargetValidator creates a new target validator
func NewTargetValidator() *TargetValidator {
	return &TargetValidator{
		AllowedCIDRs: []string{},
		AllowedIPs:   []string{},
		BlockedIPs:   []string{},
	}
}

// Validate checks if a target is allowed
func (tv *TargetValidator) Validate(target string) bool {
	// Check if target is in blocked list
	for _, blocked := range tv.BlockedIPs {
		if target == blocked {
			return false
		}
	}

	// If no restrictions, allow all
	if len(tv.AllowedIPs) == 0 && len(tv.AllowedCIDRs) == 0 {
		return true
	}

	// Check if target is in allowed list
	for _, allowed := range tv.AllowedIPs {
		if target == allowed {
			return true
		}
	}

	// Check if target is in allowed CIDR ranges
	for _, cidr := range tv.AllowedCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		ip := net.ParseIP(target)
		if ip != nil && ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// AddAllowedCIDR adds an allowed CIDR range
func (tv *TargetValidator) AddAllowedCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	tv.AllowedCIDRs = append(tv.AllowedCIDRs, cidr)
	return nil
}

// AddAllowedIP adds an allowed IP
func (tv *TargetValidator) AddAllowedIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	tv.AllowedIPs = append(tv.AllowedIPs, ip)
	return nil
}

// AddBlockedIP adds a blocked IP
func (tv *TargetValidator) AddBlockedIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	tv.BlockedIPs = append(tv.BlockedIPs, ip)
	return nil
}
