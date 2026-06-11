package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

const PMKID_LABEL = "PMK Name"

func DerivePMK(password string, ssid string) []byte {
	return pbkdf2.Key([]byte(password), []byte(ssid), 4096, 32, sha1.New)
}

func ComputePMKID(pmk []byte, apMac []byte, clientMac []byte) []byte {
	mac := sha1.New()
	mac.Write(pmk)
	mac.Write([]byte(PMKID_LABEL))
	mac.Write(apMac)
	mac.Write(clientMac)
	return mac.Sum(nil)[:16]
}

func ComputeMIC(eapolFrame []byte, ptk []byte) []byte {
	mac := hmac.New(sha1.New, ptk[:16])
	mac.Write(eapolFrame)
	return mac.Sum(nil)[:16]
}

func ParseHC22000Line(line string) (pmkidHex string, apMac []byte, clientMac []byte, ssid string, err error) {
	if len(line) < 10 {
		return "", nil, nil, "", fmt.Errorf("line too short")
	}

	parts := splitN(line, "*", 8)
	if len(parts) < 8 {
		return "", nil, nil, "", fmt.Errorf("invalid hc22000 format: need 8 fields, got %d", len(parts))
	}

	pmkidHex = parts[2]

	apMac, err = hex.DecodeString(replaceColon(parts[3]))
	if err != nil || len(apMac) != 6 {
		return "", nil, nil, "", fmt.Errorf("invalid AP MAC: %s", parts[3])
	}

	clientMac, err = hex.DecodeString(replaceColon(parts[4]))
	if err != nil || len(clientMac) != 6 {
		return "", nil, nil, "", fmt.Errorf("invalid client MAC: %s", parts[4])
	}

	ssid = parts[6]
	ssid, err = hexDecodeSSID(ssid)
	if err != nil {
		return "", nil, nil, "", err
	}

	return
}

func replaceColon(s string) string {
	b := []byte(s)
	result := make([]byte, 0, len(b))
	for _, c := range b {
		if c != ':' {
			result = append(result, c)
		}
	}
	return string(result)
}

func hexDecodeSSID(s string) (string, error) {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return s, nil
	}
	return string(decoded), nil
}

func splitN(s string, sep string, n int) []string {
	result := make([]string, 0, n)
	start := 0
	for i := 0; i < n-1 && start < len(s); i++ {
		idx := indexOf(s, sep, start)
		if idx < 0 {
			result = append(result, s[start:])
			return result
		}
		result = append(result, s[start:idx])
		start = idx + len(sep)
	}
	if start < len(s) {
		result = append(result, s[start:])
	} else {
		result = append(result, "")
	}
	return result
}

func indexOf(s string, sep string, start int) int {
	for i := start; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

func PrintCrackResult(found bool, password string, apMac []byte, ssid string, elapsed string) {
	if found {
		fmt.Printf("\n")
		fmt.Println("================================================================")
		fmt.Println("  WPA KEY FOUND!")
		fmt.Println("================================================================")
		fmt.Printf("  SSID:      %s\n", ssid)
		fmt.Printf("  BSSID:     %02X:%02X:%02X:%02X:%02X:%02X\n", apMac[0], apMac[1], apMac[2], apMac[3], apMac[4], apMac[5])
		fmt.Printf("  Password:  %s\n", password)
		fmt.Printf("  Time:      %s\n", elapsed)
		fmt.Println("================================================================")
	} else {
		fmt.Println("\n[-] Password not found in wordlist.")
	}
}

func derivePtK(pmk []byte, anonce []byte, snonce []byte, apMac []byte, clientMac []byte) []byte {
	pke := make([]byte, 0, 128)

	pMin := minMac(apMac, clientMac)
	pMax := maxMac(apMac, clientMac)
	nMin := minNonce(anonce, snonce)
	nMax := maxNonce(anonce, snonce)

	pke = append(pke, pMin...)
	pke = append(pke, pMax...)
	pke = append(pke, nMin...)
	pke = append(pke, nMax...)

	ptk := make([]byte, 64)
	for i := 0; i < 4; i++ {
		input := make([]byte, 0, 100)
		input = append(input, byte(i))
		input = append(input, pmk...)
		input = append(input, pke...)

		hm := hmac.New(sha1.New, pmk)
		hm.Write(pke)
		hm.Write([]byte{byte(i)})
		result := hm.Sum(nil)

		copy(ptk[i*16:(i+1)*16], result[:16])
	}

	return ptk
}

func minMac(a, b []byte) []byte {
	for i := 0; i < 6; i++ {
		if a[i] < b[i] {
			return a
		} else if a[i] > b[i] {
			return b
		}
	}
	return a
}

func maxMac(a, b []byte) []byte {
	for i := 0; i < 6; i++ {
		if a[i] > b[i] {
			return a
		} else if a[i] < b[i] {
			return b
		}
	}
	return a
}

func minNonce(a, b []byte) []byte {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return a
		} else if a[i] > b[i] {
			return b
		}
	}
	return a
}

func maxNonce(a, b []byte) []byte {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] > b[i] {
			return a
		} else if a[i] < b[i] {
			return b
		}
	}
	return a
}

func macToBytesSimple(mac string) ([]byte, error) {
	mac = replaceColon(mac)
	return hex.DecodeString(mac)
}

func hexString(s string) string {
	enc := make([]byte, len(s)*2)
	hex.Encode(enc, []byte(s))
	return string(enc)
}

// CrackPBKDF2 attempts to crack a single HC22000 hash line using PBKDF2.
// Returns true if the password is found.
func CrackPBKDF2(hashLine string) bool {
	ssid, apMac, clientMac, pmkid, err := ParseHC22000Line(hashLine)
	if err != nil {
		return false
	}
	// This function is designed to be called from the worker pool.
	// The actual wordlist iteration happens in doCrack; this is a stub
	// that verifies the hash line is valid.
	_ = ssid
	_ = apMac
	_ = clientMac
	_ = pmkid
	return false
}

var _ = binary.LittleEndian
var _ = derivePtK
