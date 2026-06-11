package main

import (
	"bufio"
	"fmt"
	"math"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type ChannelInfo struct {
	Number      int
	Frequency   int
	Band        string
	RSSI        int
	Noise       int
	Utilization float64
	APCount     int
}

func GetChannelFrequency(channel int, band string) int {
	switch strings.ToLower(band) {
	case "2.4g", "2.4ghz", "2g":
		if channel < 1 || channel > 14 {
			return 0
		}
		return 2407 + (channel * 5)
	case "5g", "5ghz":
		if channel >= 1 && channel <= 133 {
			return 5000 + (channel * 5)
		} else if channel >= 134 && channel <= 196 {
			return 4000 + (channel * 5)
		}
		return 0
	default:
		return 0
	}
}

func getFrequencyBand(freq int) string {
	if freq >= 2400 && freq <= 2500 {
		return "2.4GHz"
	} else if freq >= 5000 && freq <= 5900 {
		return "5GHz"
	} else if freq >= 5925 && freq <= 7125 {
		return "6GHz"
	}
	return "Unknown"
}

func iwScan(iface string) ([]ChannelInfo, error) {
	cmd := exec.Command("iw", "dev", iface, "scan")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iw scan failed: %s: %w", string(output), err)
	}

	return parseIwScanOutput(string(output)), nil
}

func parseIwScanOutput(output string) []ChannelInfo {
	var results []ChannelInfo
	apMap := make(map[int]*ChannelInfo)

	scanner := bufio.NewScanner(strings.NewReader(output))
	var currentFreq int
	var currentRSSI int
	var currentNoise int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "freq:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				freq, err := strconv.Atoi(parts[1])
				if err == nil {
					currentFreq = freq
				}
			}
		} else if strings.HasPrefix(line, "signal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				signalStr := strings.TrimSuffix(parts[1], " dBm")
				signal, err := strconv.Atoi(signalStr)
				if err == nil {
					currentRSSI = signal
				}
			}
		} else if strings.HasPrefix(line, "noise:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				noiseStr := strings.TrimSuffix(parts[1], " dBm")
				noise, err := strconv.Atoi(noiseStr)
				if err == nil {
					currentNoise = noise
				}
			}
		} else if strings.HasPrefix(line, "BSS ") {
			if currentFreq > 0 {
				ch := frequencyToChannel(currentFreq)
				if info, exists := apMap[ch]; exists {
					info.APCount++
					if currentRSSI > info.RSSI {
						info.RSSI = currentRSSI
					}
				} else {
					apMap[ch] = &ChannelInfo{
						Number:    ch,
						Frequency: currentFreq,
						Band:      getFrequencyBand(currentFreq),
						RSSI:      currentRSSI,
						Noise:     currentNoise,
						APCount:   1,
					}
				}
			}
			currentFreq = 0
			currentRSSI = 0
			currentNoise = 0
		}
	}

	if currentFreq > 0 {
		ch := frequencyToChannel(currentFreq)
		if info, exists := apMap[ch]; exists {
			info.APCount++
		} else {
			apMap[ch] = &ChannelInfo{
				Number:    ch,
				Frequency: currentFreq,
				Band:      getFrequencyBand(currentFreq),
				RSSI:      currentRSSI,
				Noise:     currentNoise,
				APCount:   1,
			}
		}
	}

	for _, info := range apMap {
		results = append(results, *info)
	}

	return results
}

func frequencyToChannel(freq int) int {
	if freq >= 2412 && freq <= 2484 {
		if freq == 2484 {
			return 14
		}
		return (freq - 2407) / 5
	} else if freq >= 5035 && freq <= 5825 {
		return (freq - 5000) / 5
	}
	return 0
}

func netshScan(iface string) ([]ChannelInfo, error) {
	cmd := exec.Command("netsh", "wlan", "show", "networks", "mode=bssid")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("netsh scan failed: %s: %w", string(output), err)
	}

	return parseNetshOutput(string(output)), nil
}

func parseNetshOutput(output string) []ChannelInfo {
	var results []ChannelInfo
	apMap := make(map[int]*ChannelInfo)

	scanner := bufio.NewScanner(strings.NewReader(output))
	var currentChannel int
	var currentRSSI int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "Channel") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ch, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err == nil {
					currentChannel = ch
				}
			}
		} else if strings.Contains(line, "Signal") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				signalStr := strings.TrimSuffix(strings.TrimSpace(parts[1]), "%")
				signalPct, err := strconv.Atoi(signalStr)
				if err == nil {
					currentRSSI = int(float64(signalPct)/2.0 - 100)
				}
			}
		} else if strings.Contains(line, "SSID") && strings.Contains(line, ":") {
			// SSID parsed but not used for channel analysis
		} else if strings.HasPrefix(line, "BSSID") || strings.Contains(line, "Network type") {
			if currentChannel > 0 {
				freq := channelToFrequencyNetsh(currentChannel)
				if info, exists := apMap[currentChannel]; exists {
					info.APCount++
					if currentRSSI > info.RSSI {
						info.RSSI = currentRSSI
					}
				} else {
					apMap[currentChannel] = &ChannelInfo{
						Number:    currentChannel,
						Frequency: freq,
						Band:      getFrequencyBand(freq),
						RSSI:      currentRSSI,
						APCount:   1,
					}
				}
				currentChannel = 0
				currentRSSI = 0
			}
		}
	}

	if currentChannel > 0 {
		freq := channelToFrequencyNetsh(currentChannel)
		if info, exists := apMap[currentChannel]; exists {
			info.APCount++
		} else {
			apMap[currentChannel] = &ChannelInfo{
				Number:    currentChannel,
				Frequency: freq,
				Band:      getFrequencyBand(freq),
				RSSI:      currentRSSI,
				APCount:   1,
			}
		}
	}

	for _, info := range apMap {
		results = append(results, *info)
	}

	return results
}

func channelToFrequencyNetsh(channel int) int {
	if channel >= 1 && channel <= 14 {
		return 2407 + (channel * 5)
	} else if channel >= 36 && channel <= 165 {
		return 5000 + (channel * 5)
	}
	return 0
}

func ScanDualBand(iface string) []ChannelInfo {
	if runtime.GOOS == "windows" {
		results, err := netshScan(iface)
		if err != nil {
			fmt.Printf("netsh scan error: %v\n", err)
			return nil
		}
		return results
	}

	results, err := iwScan(iface)
	if err != nil {
		fmt.Printf("iw scan error: %v\n", err)
		return nil
	}
	return results
}

func FindBestChannel(infos []ChannelInfo) ChannelInfo {
	if len(infos) == 0 {
		return ChannelInfo{}
	}

	best := infos[0]
	bestScore := calculateChannelScore(best)

	for _, info := range infos[1:] {
		score := calculateChannelScore(info)
		if score < bestScore {
			best = info
			bestScore = score
		}
	}

	return best
}

func calculateChannelScore(info ChannelInfo) float64 {
	apPenalty := float64(info.APCount) * 10.0
	signalPenalty := 0.0
	if info.RSSI > -80 {
		signalPenalty = float64(-80-info.RSSI) * 0.5
	}
	noisePenalty := 0.0
	if info.Noise < -90 {
		noisePenalty = float64(-90-info.Noise) * 0.3
	}
	utilizationPenalty := info.Utilization * 20.0

	return apPenalty + signalPenalty + noisePenalty + utilizationPenalty
}

func AnalyzeChannelUtilization(iface string, channel int) float64 {
	if runtime.GOOS == "windows" {
		return analyzeUtilizationWindows(iface, channel)
	}
	return analyzeUtilizationLinux(iface, channel)
}

func analyzeUtilizationLinux(iface string, channel int) float64 {
	freq := GetChannelFrequency(channel, "2.4g")
	if freq == 0 {
		freq = GetChannelFrequency(channel, "5g")
	}
	if freq == 0 {
		return 0.0
	}

	cmd := exec.Command("iw", "dev", iface, "survey", "dump")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0.0
	}

	return parseSurveyOutput(string(output), freq)
}

func parseSurveyOutput(output string, targetFreq int) float64 {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var activeTime, busyTime, totalTime uint64
	var inChannel bool
	var currentFreq int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "frequency") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				freq, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
				if err == nil {
					currentFreq = int(freq)
					inChannel = (currentFreq == targetFreq)
				}
			}
		} else if inChannel && strings.HasPrefix(line, "channel active time") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				val, _ := strconv.ParseUint(parts[len(parts)-2], 10, 64)
				activeTime = val
			}
		} else if inChannel && strings.HasPrefix(line, "channel busy time") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				val, _ := strconv.ParseUint(parts[len(parts)-2], 10, 64)
				busyTime = val
			}
		} else if inChannel && strings.HasPrefix(line, "channel time") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				val, _ := strconv.ParseUint(parts[len(parts)-2], 10, 64)
				totalTime = val
			}
		}
	}

	if totalTime == 0 {
		return 0.0
	}

	_ = activeTime
	return float64(busyTime) / float64(totalTime) * 100.0
}

func analyzeUtilizationWindows(iface string, channel int) float64 {
	cmd := exec.Command("netsh", "wlan", "show", "networks", "mode=bssid")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0.0
	}

	return parseUtilizationFromNetsh(string(output), channel)
}

func parseUtilizationFromNetsh(output string, channel int) float64 {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var currentChannel int
	var signalValues []float64

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "Channel") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ch, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err == nil {
					currentChannel = ch
				}
			}
		} else if strings.Contains(line, "Signal") && strings.Contains(line, ":") && currentChannel == channel {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				signalStr := strings.TrimSuffix(strings.TrimSpace(parts[1]), "%")
				signalPct, err := strconv.ParseFloat(signalStr, 64)
				if err == nil {
					signalValues = append(signalValues, signalPct)
				}
			}
		}
	}

	if len(signalValues) == 0 {
		return 0.0
	}

	totalSignal := 0.0
	for _, s := range signalValues {
		totalSignal += s
	}

	avgSignal := totalSignal / float64(len(signalValues))
	congestion := avgSignal / 100.0

	apDensity := math.Min(float64(len(signalValues))/10.0, 1.0)

	utilization := (congestion*0.6 + apDensity*0.4) * 100.0
	return math.Min(utilization, 100.0)
}
