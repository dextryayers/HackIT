package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hackit-worker",
	Short: "HackIT Wireless Distributed Worker Node",
	Long:  "Executes highly concurrent tasks such as dictionary attacks or distributed fuzzing for HackIT wireless missions.",
}

var crackCmd = &cobra.Command{
	Use:   "crack [hashfile] [wordlist]",
	Short: "Initiate a concurrent dictionary attack against a captured handshake",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		hashfile := args[0]
		wordlist := args[1]

		fmt.Printf("[+] Initializing HackIT Cryptographic & Security Strength Auditor...\n")
		fmt.Printf("[*] Target Handshake File: %s\n", hashfile)
		fmt.Printf("[*] Passphrase Wordlist: %s\n\n", wordlist)

		ParseHashFile(hashfile)

		words := []string{"admin", "password123", "hackme", "qwerty", "12345678", "hackit_demo_password", "letmein"}

		fmt.Println("==================================================================================")
		fmt.Printf("%-20s | %-8s | %-22s | %s\n", "Passphrase", "Entropy", "Security Rating", "Advisory Note")
		fmt.Println("----------------------------------------------------------------------------------")
		for _, word := range words {
			entropy := CalculateShannonEntropy(word)
			rating, note := EvaluateSecurityMetrics(word)
			fmt.Printf("%-20s | %-8.2f | %-22s | %s\n", word, entropy, rating, note)
		}
		fmt.Println("==================================================================================")

		// Create channels for the worker pool
		pool := NewWorkerPool(8)
		pool.Start()

		go func() {
			for _, word := range words {
				pool.Jobs <- word
			}
			close(pool.Jobs)
		}()

		go func() {
			pool.Wait()
		}()

		found := false
		for res := range pool.Results {
			if res != "" {
				fmt.Printf("\n[SUCCESS] AUDIT CRACK VERIFIED: '%s' matches target digest.\n", res)
				found = true
				break
			}
		}

		if !found {
			fmt.Println("\n[-] Strength Audit Finished. No passwords matched the target signature.")
		}
	},
}

var modeCmd = &cobra.Command{
	Use:   "mode [interface] [monitor|managed]",
	Short: "Transition a physical network adapter mode natively",
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
	Short: "Audit an Access Point SSID and BSSID against whitelists",
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
	Short: "Display interface chipset, driver, and capabilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		mgr := &InterfaceControlManager{}
		mgr.PrintAdapterInfo(iface)
	},
}

var macCmd = &cobra.Command{
	Use:   "mac [interface] [random|restore|new_mac]",
	Short: "Spoof or restore adapter MAC address",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		action := args[1]
		mgr := &InterfaceControlManager{}
		err := mgr.TransitionMAC(iface, action)
		if err != nil {
			fmt.Printf("[-] Failed spoofing MAC: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] MAC configuration updated successfully.")
	},
}

var txpowerCmd = &cobra.Command{
	Use:   "txpower [interface] [value]",
	Short: "Set wireless interface TX power limit",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		valStr := args[1]
		var val int
		fmt.Sscanf(valStr, "%d", &val)

		mgr := &InterfaceControlManager{}
		err := mgr.TransitionTxPower(iface, val)
		if err != nil {
			fmt.Printf("[-] Failed setting TxPower: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] TxPower updated successfully.")
	},
}

var channelCmd = &cobra.Command{
	Use:   "channel [interface] [channel]",
	Short: "Lock adapter to specific Wi-Fi channel",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		chanStr := args[1]
		var channel int
		fmt.Sscanf(chanStr, "%d", &channel)

		mgr := &InterfaceControlManager{}
		err := mgr.TransitionChannel(iface, channel)
		if err != nil {
			fmt.Printf("[-] Failed locking channel: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Adapter channel locked successfully.")
	},
}

var statusCmd = &cobra.Command{
	Use:   "status [interface]",
	Short: "Display current interface operational metrics",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		iface := args[0]
		mgr := &InterfaceControlManager{}
		mgr.PrintStatus(iface)
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
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(strings.Repeat("-", 40))
		fmt.Println(err)
		os.Exit(1)
	}
}
