package main

import (
	"encoding/json"
	"os"
	"strings"
)

// AccessPoint defines an authorized SSID and BSSID pair
type AccessPoint struct {
	SSID  string `json:"ssid"`
	BSSID string `json:"bssid"`
}

// APAuditor handles whitelist matching logic
type APAuditor struct {
	Whitelist []AccessPoint
}

// LoadWhitelist reads the default whitelist JSON or creates a mock one if missing
func (a *APAuditor) LoadWhitelist(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		// Create default database if not exists
		defaultAPs := []AccessPoint{
			{SSID: "Enterprise-HQ", BSSID: "00:1A:2B:3C:4D:01"},
			{SSID: "Redmi Note 12", BSSID: "44:87:63:B8:AE:D2"},
			{SSID: "TP-Link", BSSID: "44:87:63:B8:AE:D3"},
		}
		data, _ := json.MarshalIndent(defaultAPs, "", "  ")
		_ = os.WriteFile(filePath, data, 0644)
		a.Whitelist = defaultAPs
		return nil
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&a.Whitelist)
	return err
}

// AuditAP compares the observed AP against the loaded whitelist
func (a *APAuditor) AuditAP(ssid, bssid string) string {
	ssidLower := strings.ToLower(ssid)
	bssidLower := strings.ToLower(bssid)

	ssidMatchFound := false
	bssidMatchFound := false

	for _, ap := range a.Whitelist {
		apSSID := strings.ToLower(ap.SSID)
		apBSSID := strings.ToLower(ap.BSSID)

		if apSSID == ssidLower {
			ssidMatchFound = true
			if apBSSID == bssidLower {
				bssidMatchFound = true
				break
			}
		}
	}

	if bssidMatchFound {
		return "AUTHORIZED (SAFE)"
	}

	if ssidMatchFound {
		// SSID matches but BSSID is different -> Evil Twin / Rogue AP Alert!
		return "ROGUE AP / EVIL TWIN (ALERT!)"
	}

	return "UNKNOWN / EXTERNAL"
}
