package main

import (
	"strconv"
	"strings"
)

type FilterResult struct {
	Filtered bool
	Reason   string
}

func FilterResponseAdvanced(res *DirResult, config *ScanConfig) FilterResult {
	if config.IncludeStatus != nil {
		if !statusInList(res.Status, config.IncludeStatus) {
			return FilterResult{true, "not-in-include-status"}
		}
	}

	if config.ExcludeStatus != nil {
		if statusInList(res.Status, config.ExcludeStatus) {
			return FilterResult{true, "exclude-status"}
		}
	}

	if config.ExcludeSizes != nil {
		for _, sizeStr := range config.ExcludeSizes {
			sizeStr = strings.TrimSpace(sizeStr)
			if sizeStr == "0" && res.Size == 0 {
				return FilterResult{true, "exclude-size-zero"}
			}
			if sizeBytes := parseSizeBytes(sizeStr); sizeBytes > 0 && res.Size == sizeBytes {
				return FilterResult{true, "exclude-size-" + sizeStr}
			}
		}
	}

	if config.MinResponseSize > 0 && res.Size < config.MinResponseSize {
		return FilterResult{true, "min-size"}
	}
	if config.MaxResponseSize > 0 && res.Size > config.MaxResponseSize {
		return FilterResult{true, "max-size"}
	}

	if config.SkipOnStatus != nil {
		if statusInList(res.Status, config.SkipOnStatus) {
			return FilterResult{true, "skip-on-status"}
		}
	}

	if config.Similarity > 0 && res.BodyHash == "" {
		return FilterResult{true, "no-bodyhash"}
	}

	return FilterResult{false, ""}
}

func parseSizeBytes(s string) int64 {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)

	if strings.HasSuffix(s, "KB") {
		val, _ := strconv.ParseFloat(strings.TrimSuffix(s, "KB"), 64)
		return int64(val * 1024)
	}
	if strings.HasSuffix(s, "MB") {
		val, _ := strconv.ParseFloat(strings.TrimSuffix(s, "MB"), 64)
		return int64(val * 1024 * 1024)
	}
	if strings.HasSuffix(s, "GB") {
		val, _ := strconv.ParseFloat(strings.TrimSuffix(s, "GB"), 64)
		return int64(val * 1024 * 1024 * 1024)
	}
	if strings.HasSuffix(s, "B") {
		val, _ := strconv.ParseInt(strings.TrimSuffix(s, "B"), 10, 64)
		return val
	}
	val, _ := strconv.ParseInt(s, 10, 64)
	return val
}

func parseStatusRangeList(s string) []int {
	var result []int
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			r := strings.SplitN(part, "-", 2)
			start, _ := strconv.Atoi(strings.TrimSpace(r[0]))
			end, _ := strconv.Atoi(strings.TrimSpace(r[1]))
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
		} else {
			val, _ := strconv.Atoi(part)
			result = append(result, val)
		}
	}
	return result
}
