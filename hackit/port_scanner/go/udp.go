package main

import (
	"fmt"
	"net"
	"time"
)

// ScanUDP performs a UDP port scan on a single port
func ScanUDP(host string, port int, timeoutMs int) (PortResult, bool) {
	address := fmt.Sprintf("%s:%d", host, port)
	serverAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return PortResult{}, false
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return PortResult{}, false
	}
	defer conn.Close()

	// UDP is connectionless, so we send a generic probe and wait for ICMP unreachable
	// or a response from the service.
	probe := []byte("\x00") // Generic null probe

	// Protocol specific probes
	if port == 53 { // DNS
		probe = []byte("\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01")
	} else if port == 123 { // NTP
		probe = make([]byte, 48)
		probe[0] = 0x1B
	} else if port == 161 { // SNMP
		probe = []byte("\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x71\x09\xb5\x82\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00")
	}

	_, err = conn.Write(probe)
	if err != nil {
		return PortResult{}, false
	}

	// Wait for response
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	if err != nil {
		// If we get an error, it might be closed (ICMP Unreachable) or filtered
		// In a real UDP scan, "no response" often means open|filtered
		svc, ver := IdentifyService(port, "", host)
		return PortResult{
			Port:    port,
			State:   "open|filtered",
			Service: svc,
			Version: ver,
		}, true
	}

	// If we got a response, it's definitely open
	banner := string(buffer[:n])
	service, version := IdentifyService(port, banner, host)
	if version == "" {
		version = ExtractVersion(service, banner)
	}
	return PortResult{
		Port:    port,
		State:   "open",
		Service: service,
		Banner:  banner,
		Version: version,
	}, true
}
