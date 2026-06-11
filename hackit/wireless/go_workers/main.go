package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hackit-worker",
	Short: "HackIT Wireless Distributed Worker Node",
	Long:  "Wireless penetration testing worker: WPA cracking, channel hopping, AP auditing, interface control",
}

var crackCmd = &cobra.Command{
	Use:   "crack [hashfile] [wordlist]",
	Short: "Crack WPA/WPA2 handshake using dictionary attack",
	Long:  "Crack WPA/WPA2 PMKID (hc22000 format) with dictionary attack using PBKDF2-SHA1",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		hashfile := args[0]
		wordlist := args[1]

		fmt.Printf("[+] HackIT WPA Cracker v2.0\n")
		fmt.Printf("[*] Hash file:   %s\n", hashfile)
		fmt.Printf("[*] Wordlist:    %s\n\n", wordlist)

		hashFile, err := os.Open(hashfile)
		if err != nil {
			fmt.Printf("[-] Cannot open hash file: %v\n", err)
			return
		}
		defer hashFile.Close()

		wordFile, err := os.Open(wordlist)
		if err != nil {
			fmt.Printf("[-] Cannot open wordlist: %v\n", err)
			return
		}
		defer wordFile.Close()

		scanner := bufio.NewScanner(hashFile)
		var hashLines []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				hashLines = append(hashLines, line)
			}
		}

		if len(hashLines) == 0 {
			fmt.Println("[-] No valid hash lines found in", hashfile)
			return
		}

		fmt.Printf("[+] Loaded %d hash(es)\n", len(hashLines))

		for _, hashLine := range hashLines {
			pmkidHex, apMac, clientMac, ssid, err := ParseHC22000Line(hashLine)
			if err != nil {
				fmt.Printf("[-] Skipping invalid hash line: %v\n", err)
				continue
			}

			targetPMKID, err := hexStringToBytes(pmkidHex)
			if err != nil {
				fmt.Printf("[-] Invalid PMKID hex: %v\n", err)
				continue
			}

			fmt.Printf("\n[*] Cracking SSID: %s\n", ssid)
			fmt.Printf("[*] BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", apMac[0], apMac[1], apMac[2], apMac[3], apMac[4], apMac[5])
			fmt.Printf("[*] Target PMKID: %s\n", pmkidHex)
			fmt.Println("[*] Starting dictionary attack...")
			fmt.Println()

			start := time.Now()
			found, password := doCrack(wordlist, ssid, apMac, clientMac, targetPMKID)
			elapsed := time.Since(start).String()

			PrintCrackResult(found, password, apMac, ssid, elapsed)
		}
	},
}

func doCrack(wordlistPath string, ssid string, apMac []byte, clientMac []byte, targetPMKID []byte) (bool, string) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Printf("[-] Cannot open wordlist: %v\n", err)
		return false, ""
	}
	defer file.Close()

	total := 0
	start := time.Now()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password == "" {
			continue
		}

		total++

		if total%10000 == 0 {
			elapsed := time.Since(start).Seconds()
			rate := float64(total) / elapsed
			fmt.Printf("\r[+] Tested: %d passwords | Rate: %.0f p/s | Last: %s", total, rate, password)
		}

		pmk := DerivePMK(password, ssid)

		pmkid := ComputePMKID(pmk, apMac, clientMac)

		if hmacEqual(pmkid, targetPMKID) {
			fmt.Println()
			return true, password
		}
	}

	return false, ""
}

func hexStringToBytes(s string) ([]byte, error) {
	decoded := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		_, err := fmt.Sscanf(s[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		decoded[i/2] = b
	}
	return decoded, nil
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
		ssid := "HackIT"
		if len(args) > 2 {
			ssid = args[2]
		}
		bssid := []byte{0x02, 0x00, 0x01, 0x02, 0x03, 0x04}
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

func init() {
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
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(strings.Repeat("-", 40))
		fmt.Println(err)
		os.Exit(1)
	}
}
