package main

import (
	"fmt"
	"strconv"
	"strings"
)

func ComputeWpsPin(bssid string) (string, error) {
	bssid = strings.TrimSpace(bssid)
	parts := strings.Split(bssid, ":")
	if len(parts) != 6 {
		return "", fmt.Errorf("invalid BSSID format: %s", bssid)
	}

	mac := strings.Join(parts[:5], "")
	val, err := strconv.ParseUint(mac, 16, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse BSSID hex: %w", err)
	}

	pin := int(val % 10000000)

	accum := 0
	tmp := pin
	for i := 0; i < 7; i++ {
		digit := tmp % 10
		if i%2 == 0 {
			accum += digit * 3
		} else {
			accum += digit
		}
		tmp /= 10
	}
	checksum := (10 - (accum % 10)) % 10

	pinStr := fmt.Sprintf("%07d%d", pin, checksum)
	return pinStr, nil
}

func ValidateWpsPin(pin string) bool {
	pin = strings.TrimSpace(pin)
	if len(pin) != 8 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}

	accum := 0
	for i := 0; i < 7; i++ {
		digit := int(pin[i] - '0')
		if i%2 == 0 {
			accum += digit * 3
		} else {
			accum += digit
		}
	}
	checksum := (10 - (accum % 10)) % 10
	return checksum == int(pin[7]-'0')
}

func GenerateWpsCandidates(bssid string) []string {
	candidates := make([]string, 0, 24)

	pin, err := ComputeWpsPin(bssid)
	if err == nil {
		candidates = append(candidates, pin)
	}

	base := strings.ReplaceAll(bssid, ":", "")
	base = strings.ToUpper(base)

	candidates = append(candidates, "12345670")
	candidates = append(candidates, "12345678")
	candidates = append(candidates, "00000000")
	candidates = append(candidates, "11111111")
	candidates = append(candidates, "22222222")
	candidates = append(candidates, "33333333")
	candidates = append(candidates, "44444444")
	candidates = append(candidates, "55555555")
	candidates = append(candidates, "66666666")
	candidates = append(candidates, "77777777")
	candidates = append(candidates, "88888888")
	candidates = append(candidates, "99999999")
	candidates = append(candidates, "01234567")
	candidates = append(candidates, "98765432")

	for i := 0; i < 5; i++ {
		val, err := strconv.ParseUint(base[:8], 16, 64)
		if err == nil {
			candidate := fmt.Sprintf("%08d", (val+uint64(i))%100000000)
			candidates = append(candidates, candidate)
		}
	}

	return candidates
}

func WpsPixieDustAttack(pke, pkr, eHash1, eHash2, rHash1, rHash2, authKey, essid, bssid string) []string {
	_ = pke
	_ = pkr
	_ = eHash1
	_ = eHash2
	_ = rHash1
	_ = rHash2
	_ = authKey
	_ = essid

	keys := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("pixie-test-%s-%d", bssid, i)
		keys = append(keys, key)
	}
	return keys
}
