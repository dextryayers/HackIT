package main

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// OutputFormat represents different output formats
type OutputFormat string

const (
	OutputNormal   OutputFormat = "normal"
	OutputXML      OutputFormat = "xml"
	OutputGrepable OutputFormat = "grepable"
	OutputJSON     OutputFormat = "json"
)

// ScanReport represents a complete scan report
type ScanReport struct {
	XMLName     xml.Name     `json:"-" xml:"nmaprun"`
	Scanner     string       `json:"scanner" xml:"scanner,attr"`
	Args        string       `json:"args" xml:"args,attr"`
	StartStr    string       `json:"start" xml:"startstr,attr"`
	Version     string       `json:"version" xml:"version,attr"`
	StartTime   time.Time    `json:"start_time" xml:"start"`
	ElapsedTime float64      `json:"elapsed_time" xml:"elapsed"`
	Hosts       []HostReport `json:"hosts" xml:"host"`
	RunStats    RunStats     `json:"run_stats" xml:"runstats"`
}

// HostReport represents a single host scan result
type HostReport struct {
	XMLName   xml.Name    `json:"-" xml:"host"`
	StartTime string      `json:"start_time" xml:"starttime,attr"`
	EndTime   string      `json:"end_time" xml:"endtime,attr"`
	Status    HostStatus  `json:"status" xml:"status"`
	Address   Address     `json:"address" xml:"address"`
	Hostnames Hostnames   `json:"hostnames,omitempty" xml:"hostnames"`
	Ports     Ports       `json:"ports" xml:"ports"`
	OS        OSReport    `json:"os,omitempty" xml:"os"`
	Trace     *TraceRoute `json:"trace,omitempty" xml:"trace"`
}

// HostStatus represents host status
type HostStatus struct {
	State  string `json:"state" xml:"state,attr"`
	Reason string `json:"reason" xml:"reason,attr"`
}

// Address represents IP address
type Address struct {
	XMLName  xml.Name `json:"-" xml:"address"`
	Addr     string   `json:"addr" xml:"addr,attr"`
	AddrType string   `json:"addrtype" xml:"addrtype,attr"`
}

// Hostnames represents hostnames
type Hostnames struct {
	XMLName xml.Name   `json:"-" xml:"hostnames"`
	Names   []Hostname `json:"hostnames,omitempty" xml:"hostname"`
}

// Hostname represents a single hostname
type Hostname struct {
	XMLName xml.Name `json:"-" xml:"hostname"`
	Name    string   `json:"name" xml:"name,attr"`
	Type    string   `json:"type" xml:"type,attr"`
}

// Ports represents port scan results
type Ports struct {
	XMLName xml.Name     `json:"-" xml:"ports"`
	Extra   string       `json:"extra,omitempty" xml:"extraports,attr"`
	Ports   []PortReport `json:"ports,omitempty" xml:"port"`
}

// PortReport represents a single port result
type PortReport struct {
	XMLName  xml.Name     `json:"-" xml:"port"`
	Protocol string       `json:"protocol" xml:"protocol,attr"`
	PortID   int          `json:"port_id" xml:"portid,attr"`
	State    PortState    `json:"state" xml:"state"`
	Service  *ServiceInfo `json:"service,omitempty" xml:"service"`
}

// PortState represents port state
type PortState struct {
	State  string `json:"state" xml:"state,attr"`
	Reason string `json:"reason,omitempty" xml:"reason,attr"`
}

// ServiceInfo represents service information
type ServiceInfo struct {
	XMLName   xml.Name `json:"-" xml:"service"`
	Name      string   `json:"name" xml:"name,attr"`
	Product   string   `json:"product,omitempty" xml:"product,attr"`
	Version   string   `json:"version,omitempty" xml:"version,attr"`
	ExtraInfo string   `json:"extra_info,omitempty" xml:"extrainfo,attr"`
	Method    string   `json:"method,omitempty" xml:"method,attr"`
	Conf      string   `json:"conf,omitempty" xml:"conf,attr"`
}

// OSReport represents OS detection results
type OSReport struct {
	XMLName xml.Name  `json:"-" xml:"os"`
	Matches []OSMatch `json:"matches,omitempty" xml:"osmatch"`
}

// OSMatch represents OS match
type OSMatch struct {
	XMLName  xml.Name `json:"-" xml:"osmatch"`
	Name     string   `json:"name" xml:"name,attr"`
	Accuracy int      `json:"accuracy" xml:"accuracy,attr"`
	Line     int      `json:"line" xml:"line,attr"`
}

// TraceRoute represents traceroute results
type TraceRoute struct {
	XMLName xml.Name `json:"-" xml:"trace"`
	Hops    []Hop    `json:"hops,omitempty" xml:"hop"`
}

// Hop represents a traceroute hop
type Hop struct {
	XMLName xml.Name `json:"-" xml:"hop"`
	TTL     int      `json:"ttl" xml:"ttl,attr"`
	IPAddr  string   `json:"ip" xml:"ipaddr,attr"`
	RTT     string   `json:"rtt" xml:"rtt,attr"`
	Host    string   `json:"host,omitempty" xml:"host,attr"`
}

// RunStats represents scan statistics
type RunStats struct {
	XMLName  xml.Name  `json:"-" xml:"runstats"`
	Finished Finished  `json:"finished" xml:"finished"`
	Hosts    HostStats `json:"hosts" xml:"hosts"`
}

// Finished represents scan completion info
type Finished struct {
	XMLName    xml.Name `json:"-" xml:"finished"`
	TimeStr    string   `json:"time" xml:"time,attr"`
	Elapsed    float64  `json:"elapsed" xml:"elapsed,attr"`
	Summary    string   `json:"summary" xml:"summary,attr"`
	ExitStatus string   `json:"exit" xml:"exit,attr"`
}

// HostStats represents host statistics
type HostStats struct {
	XMLName xml.Name `json:"-" xml:"hosts"`
	Up      int      `json:"up" xml:"up,attr"`
	Down    int      `json:"down" xml:"down,attr"`
	Total   int      `json:"total" xml:"total,attr"`
}

// OutputFormatter handles output formatting
type OutputFormatter struct {
	Format OutputFormat
}

// NewOutputFormatter creates a new output formatter
func NewOutputFormatter(format OutputFormat) *OutputFormatter {
	return &OutputFormatter{
		Format: format,
	}
}

// FormatOutput formats scan results according to the specified format
func (of *OutputFormatter) FormatOutput(report ScanReport) (string, error) {
	switch of.Format {
	case OutputXML:
		return of.formatXML(report)
	case OutputGrepable:
		return of.formatGrepable(report), nil
	case OutputJSON:
		return of.formatJSON(report)
	case OutputNormal:
		return of.formatNormal(report), nil
	default:
		return of.formatNormal(report), nil
	}
}

// formatXML formats output as XML
func (of *OutputFormatter) formatXML(report ScanReport) (string, error) {
	data, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// formatGrepable formats output in grepable format
func (of *OutputFormatter) formatGrepable(report ScanReport) string {
	var output strings.Builder

	for _, host := range report.Hosts {
		for _, port := range host.Ports.Ports {
			line := fmt.Sprintf("Host: %s (%s)\tPorts: %d/%s/%s/%s/%s",
				host.Address.Addr,
				host.Status.State,
				port.PortID,
				port.State.State,
				port.Service.Name,
				port.Service.Product,
				port.Service.Version,
			)
			output.WriteString(line + "\n")
		}
	}

	return output.String()
}

// formatJSON formats output as JSON
func (of *OutputFormatter) formatJSON(report ScanReport) (string, error) {
	// Use json.Marshal here - placeholder
	return "{}", nil
}

// formatNormal formats output in normal human-readable format
func (of *OutputFormatter) formatNormal(report ScanReport) string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("Starting Nmap %s at %s\n", report.Version, report.StartStr))
	output.WriteString(fmt.Sprintf("Scanned %d hosts, %d up, %d down\n",
		report.RunStats.Hosts.Total,
		report.RunStats.Hosts.Up,
		report.RunStats.Hosts.Down))
	output.WriteString(fmt.Sprintf("Scan completed in %.2f seconds\n\n", report.ElapsedTime))

	for _, host := range report.Hosts {
		output.WriteString(fmt.Sprintf("Host: %s (%s)\n", host.Address.Addr, host.Status.State))
		output.WriteString(fmt.Sprintf("  Address: %s (%s)\n", host.Address.Addr, host.Address.AddrType))

		if len(host.Hostnames.Names) > 0 {
			output.WriteString("  Hostnames:\n")
			for _, hostname := range host.Hostnames.Names {
				output.WriteString(fmt.Sprintf("    %s (%s)\n", hostname.Name, hostname.Type))
			}
		}

		output.WriteString("  Ports:\n")
		output.WriteString("    PORT      STATE    SERVICE    VERSION\n")
		output.WriteString("    ----      -----    -------    -------\n")

		for _, port := range host.Ports.Ports {
			serviceInfo := ""
			serviceVersion := ""
			if port.Service != nil {
				serviceInfo = fmt.Sprintf("%s %s %s",
					port.Service.Name,
					port.Service.Product,
					port.Service.Version)
				serviceVersion = port.Service.Version
			}
			output.WriteString(fmt.Sprintf("    %-9d %-9s %-10s %s\n",
				port.PortID,
				port.State.State,
				serviceInfo,
				serviceVersion,
			))
		}

		if len(host.OS.Matches) > 0 {
			output.WriteString("  OS detection:\n")
			for _, os := range host.OS.Matches {
				output.WriteString(fmt.Sprintf("    %s (accuracy %d%%)\n", os.Name, os.Accuracy))
			}
		}

		output.WriteString("\n")
	}

	return output.String()
}

// ConvertToReport converts scan results to ScanReport
func ConvertToReport(host string, results []PortResult, osInfo OSInfo) ScanReport {
	report := ScanReport{
		Scanner:     "HackIt Port Scanner",
		Version:     "3.0",
		StartStr:    time.Now().Format("2006-01-02 15:04:05"),
		StartTime:   time.Now(),
		ElapsedTime: 0,
	}

	hostReport := HostReport{
		StartTime: time.Now().Format("2006-01-02 15:04:05"),
		EndTime:   time.Now().Format("2006-01-02 15:04:05"),
		Status: HostStatus{
			State:  "up",
			Reason: "syn-ack",
		},
		Address: Address{
			Addr:     host,
			AddrType: "ipv4",
		},
	}

	ports := Ports{}
	for _, result := range results {
		port := PortReport{
			Protocol: "tcp",
			PortID:   result.Port,
			State: PortState{
				State:  result.State,
				Reason: "syn-ack",
			},
		}

		if result.Service != "" || result.Banner != "" {
			port.Service = &ServiceInfo{
				Name:      result.Service,
				Product:   result.Version,
				Version:   result.Version,
				ExtraInfo: result.Banner,
				Method:    "probed",
				Conf:      "10",
			}
		}

		ports.Ports = append(ports.Ports, port)
	}

	hostReport.Ports = ports

	if osInfo.Name != "Unknown" {
		hostReport.OS = OSReport{
			Matches: []OSMatch{
				{
					Name:     osInfo.Name,
					Accuracy: int(osInfo.Confidence * 100),
				},
			},
		}
	}

	report.Hosts = []HostReport{hostReport}

	upCount := 1
	downCount := 0
	if len(results) == 0 {
		upCount = 0
		downCount = 1
	}

	report.RunStats = RunStats{
		Finished: Finished{
			TimeStr: time.Now().Format("2006-01-02 15:04:05"),
			Elapsed: report.ElapsedTime,
			Summary: fmt.Sprintf("%d host scanned. %d host up, %d host down in %.2f seconds",
				upCount+downCount, upCount, downCount, report.ElapsedTime),
			ExitStatus: "success",
		},
		Hosts: HostStats{
			Up:    upCount,
			Down:  downCount,
			Total: upCount + downCount,
		},
	}

	return report
}

// SaveToFile saves formatted output to a file
func (of *OutputFormatter) SaveToFile(report ScanReport, filename string) error {
	output, err := of.FormatOutput(report)
	if err != nil {
		return err
	}

	// Write to file - placeholder implementation
	_ = output
	_ = filename
	return nil
}

// GetOutputExtension returns the file extension for a format
func GetOutputExtension(format OutputFormat) string {
	switch format {
	case OutputXML:
		return ".xml"
	case OutputGrepable:
		return ".gnmap"
	case OutputJSON:
		return ".json"
	default:
		return ".txt"
	}
}
