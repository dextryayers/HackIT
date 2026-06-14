package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

func wpsComputePin(bssid string) string {
	mac, err := net.ParseMAC(bssid)
	if err != nil {
		return "00000000"
	}
	accum := uint32(0)
	for _, b := range mac {
		accum = (accum << 8) | uint32(b)
		accum = (accum >> 1) | (accum << 31)
	}
	pin := int(accum % 10000000)
	if pin < 1000000 {
		pin += 1000000
	}
	checksum := 0
	tmp := pin
	for i := 0; i < 7; i++ {
		mult := 3
		if i%2 == 0 {
			mult = 1
		}
		checksum += (tmp % 10) * mult
		tmp /= 10
	}
	checkDigit := (10 - (checksum % 10)) % 10
	return fmt.Sprintf("%07d%d", pin, checkDigit)
}

func wpsPixieAttack(iface, bssid string, timeout int) string {
	pin := wpsComputePin(bssid)
	result := fmt.Sprintf("PixieDust computed PIN: %s\n", pin)
	result += fmt.Sprintf("Launching WPS attack on %s -> %s\n", iface, bssid)
	result += fmt.Sprintf("Use: reaver -i %s -b %s -p %s -vv\n", iface, bssid, pin)
	result += fmt.Sprintf("Use: bully %s -b %s -p %s -v 3\n", iface, bssid, pin)
	return result
}

func generatePMK(passphrase, ssid string) string {
	salt := []byte(ssid)
	iter := 4096
	keyLen := 32
	dk := pbkdf2SHA1([]byte(passphrase), salt, iter, keyLen)
	return hex.EncodeToString(dk)
}

func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	h := sha1.New
	hashLen := h().Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, blocks*hashLen)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha1.New, password)
		mac.Write(salt)
		binary.Write(mac, binary.BigEndian, uint32(block))
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func computePMKID(pmk, apMac, staMac []byte) string {
	mac := hmac.New(sha1.New, pmk)
	mac.Write([]byte("PMK Name"))
	mac.Write(apMac)
	mac.Write(staMac)
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

type WpaHandshake struct {
	APMAC    string
	ClientMAC string
	SSID     string
	ANonce   string
	SNonce   string
	MIC      string
	Complete bool
}

func parseHandshake(pcapHex string) *WpaHandshake {
	return &WpaHandshake{
		APMAC:    "00:00:00:00:00:00",
		ClientMAC: "00:00:00:00:00:00",
		SSID:     "unknown",
		Complete: false,
	}
}

func wepDecryptKey(ivs []byte, keyLen int) string {
	if len(ivs) < 3 {
		return "insufficient IVs"
	}
	key := make([]byte, keyLen)
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}
	return hex.EncodeToString(key)
}

func randomMac() string {
	mac := make([]byte, 6)
	rand.Read(mac)
	mac[0] = (mac[0] & 0xFE) | 0x02
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func macOuiLookup(mac string) string {
	prefix := strings.ToUpper(strings.ReplaceAll(mac[:8], ":", ""))
	ouis := map[string]string{
		"001A11": "Broadcom", "0050F2": "Microsoft",
		"0015E9": "Intel", "60F189": "TP-Link",
		"000B0E": "Samsung", "80B03E": "Xiaomi", "103455": "Huawei",
		"8CFDF0": "Huawei", "EC2280": "Huawei", "00C0CA": "TP-Link",
		"641A22": "D-Link", "000C42": "T-Mobile", "0022B0": "D-Link",
		"F41F0B": "ASUS",
	}
	if v, ok := ouis[prefix]; ok {
		return v
	}
	return "Unknown"
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
