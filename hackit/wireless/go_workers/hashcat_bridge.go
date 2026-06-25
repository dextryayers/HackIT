package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type HashEntry struct {
	Version    int
	PMKID      string
	APNonce    string
	ClientNonce string
	APMac      []byte
	ClientMac  []byte
	ESSID      string
	KeyVersion int
	KeyData    string
}

func hexToBytes(hex string) ([]byte, error) {
	hex = strings.TrimSpace(hex)
	if len(hex)%2 != 0 {
		hex = "0" + hex
	}
	bytes := make([]byte, 0, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		if i+2 > len(hex) {
			return nil, fmt.Errorf("invalid hex string length")
		}
		b, err := strconv.ParseUint(hex[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex character at position %d: %w", i, err)
		}
		bytes = append(bytes, byte(b))
	}
	return bytes, nil
}

func bytesToHex(data []byte) string {
	var sb strings.Builder
	sb.Grow(len(data) * 2)
	for _, b := range data {
		sb.WriteByte(hexChars[b>>4])
		sb.WriteByte(hexChars[b&0x0f])
	}
	return sb.String()
}

const hexChars = "0123456789ABCDEF"

func bytesToMac(data []byte) string {
	if len(data) != 6 {
		return "00:00:00:00:00:00"
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		data[0], data[1], data[2], data[3], data[4], data[5])
}

func macToBytes(mac string) ([]byte, error) {
	mac = strings.TrimSpace(mac)
	mac = strings.ToUpper(mac)
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid MAC address format: %s", mac)
	}
	bytes := make([]byte, 6)
	for i, part := range parts {
		if len(part) != 2 {
			return nil, fmt.Errorf("invalid MAC octet %s at position %d", part, i)
		}
		b, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex in MAC octet %s: %w", part, err)
		}
		bytes[i] = byte(b)
	}
	return bytes, nil
}

func ParseHC22000File(path string) ([]HashEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()

	var entries []HashEntry
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseHC22000Line(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %w", lineNum, err)
		}
		entries = append(entries, *entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return entries, nil
}

func parseHC22000Line(line string) (*HashEntry, error) {
	parts := strings.Split(line, "*")
	if len(parts) < 10 {
		return nil, fmt.Errorf("expected at least 10 fields, got %d", len(parts))
	}

	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid version field %q: %w", parts[0], err)
	}

	pmkid := strings.TrimSpace(parts[1])
	apNonce := strings.TrimSpace(parts[2])
	clientNonce := strings.TrimSpace(parts[3])
	apMacHex := strings.TrimSpace(parts[4])
	clientMacHex := strings.TrimSpace(parts[5])
	essid := strings.TrimSpace(parts[6])
	keyVersionStr := strings.TrimSpace(parts[8])
	keyData := strings.TrimSpace(parts[9])

	if pmkid == "" {
		return nil, fmt.Errorf("empty PMKID")
	}

	if apNonce == "" || clientNonce == "" {
		return nil, fmt.Errorf("empty AP or client nonce")
	}

	apMac, err := hexToBytes(apMacHex)
	if err != nil {
		return nil, fmt.Errorf("invalid AP MAC: %w", err)
	}
	if len(apMac) != 6 {
		return nil, fmt.Errorf("AP MAC must be 6 bytes, got %d", len(apMac))
	}

	clientMac, err := hexToBytes(clientMacHex)
	if err != nil {
		return nil, fmt.Errorf("invalid client MAC: %w", err)
	}
	if len(clientMac) != 6 {
		return nil, fmt.Errorf("client MAC must be 6 bytes, got %d", len(clientMac))
	}

	keyVersion, err := strconv.Atoi(keyVersionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid key version %q: %w", keyVersionStr, err)
	}

	return &HashEntry{
		Version:    version,
		PMKID:      pmkid,
		APNonce:    apNonce,
		ClientNonce: clientNonce,
		APMac:      apMac,
		ClientMac:  clientMac,
		ESSID:      essid,
		KeyVersion: keyVersion,
		KeyData:    keyData,
	}, nil
}

func GenerateHC22000Line(ssid string, apMac []byte, clientMac []byte, pmkid []byte) string {
	if len(apMac) != 6 || len(clientMac) != 6 || len(pmkid) != 16 {
		return ""
	}

	return fmt.Sprintf("*%s*%s*%s*%s*%s*%s**1*%s",
		bytesToHex(pmkid),
		bytesToHex(make([]byte, 32)),
		bytesToHex(make([]byte, 32)),
		bytesToHex(apMac),
		bytesToHex(clientMac),
		"01",
		bytesToHex(make([]byte, 0)),
	)
}

func ValidateHashEntry(entry HashEntry) bool {
	if len(entry.PMKID) != 32 {
		return false
	}

	if _, err := hexToBytes(entry.PMKID); err != nil {
		return false
	}

	if len(entry.APNonce) != 64 {
		return false
	}

	if _, err := hexToBytes(entry.APNonce); err != nil {
		return false
	}

	if len(entry.ClientNonce) != 64 {
		return false
	}

	if _, err := hexToBytes(entry.ClientNonce); err != nil {
		return false
	}

	if len(entry.APMac) != 6 {
		return false
	}

	if len(entry.ClientMac) != 6 {
		return false
	}

	if entry.Version < 1 || entry.Version > 4 {
		return false
	}

	if entry.KeyVersion < 1 || entry.KeyVersion > 4 {
		return false
	}

	return true
}
