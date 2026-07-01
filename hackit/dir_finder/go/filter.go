package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func ShouldFilter(res *DirResult, config *ScanConfig) bool {
	if res == nil {
		return true
	}

	// Wildcard suppression
	if res.Status == config.WildcardStatus && res.Size == config.WildcardSize {
		return true
	}

	// Skip-on-status
	if len(config.SkipOnStatus) > 0 && statusInList(res.Status, config.SkipOnStatus) {
		return true
	}

	// Include/Exclude status
	if len(config.IncludeStatus) > 0 && !statusInList(res.Status, config.IncludeStatus) {
		return true
	}
	if len(config.ExcludeStatus) > 0 && statusInList(res.Status, config.ExcludeStatus) {
		return true
	}

	// Match/Filter status (advanced)
	if len(config.MatchStatus) > 0 && !statusInList(res.Status, config.MatchStatus) {
		return true
	}
	if len(config.FilterStatus) > 0 && statusInList(res.Status, config.FilterStatus) {
		return true
	}

	// Size filters
	if len(config.ExcludeSizes) > 0 && checkExcludeSizes(res.Size, config.ExcludeSizes) {
		return true
	}
	if config.MinResponseSize > 0 && res.Size < config.MinResponseSize {
		return true
	}
	if config.MaxResponseSize > 0 && res.Size > config.MaxResponseSize {
		return true
	}

	// Advanced size matcher/filter
	if len(config.MatchSize) > 0 && !sizeInRanges(res.Size, config.MatchSize) {
		return true
	}
	if len(config.FilterSize) > 0 && sizeInRanges(res.Size, config.FilterSize) {
		return true
	}

	// Blacklist check
	if config.Blacklists != nil {
		if blacklistedPaths, ok := config.Blacklists[res.Status]; ok {
			for _, bp := range blacklistedPaths {
				if strings.HasSuffix(res.Path, bp) {
					return true
				}
			}
		}
	}

	return false
}

func ShouldFilterBody(body []byte, res *DirResult, config *ScanConfig) bool {
	if len(body) == 0 {
		return false
	}
	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)

	// Exclude text
	if len(config.ExcludeText) > 0 {
		for _, t := range config.ExcludeText {
			if strings.Contains(bodyLower, strings.ToLower(t)) {
				return true
			}
		}
	}

	// Exclude regex
	if config.ExcludeRegexCompiled != nil {
		if config.ExcludeRegexCompiled.MatchString(bodyStr) {
			return true
		}
	}

	// Match regex
	if config.MatchRegexCompiled != nil {
		if !config.MatchRegexCompiled.MatchString(bodyStr) {
			return true
		}
	}

	// Filter regex
	if config.FilterRegex != "" {
		re, err := regexp.Compile(config.FilterRegex)
		if err == nil && re.MatchString(bodyStr) {
			return true
		}
	}

	// Match/Filter word counts
	if len(config.MatchWords) > 0 || len(config.FilterWords) > 0 {
		wordCount := countWords(bodyStr)
		if len(config.MatchWords) > 0 {
			if !countInRanges(wordCount, config.MatchWords) {
				return true
			}
		}
		if len(config.FilterWords) > 0 {
			if countInRanges(wordCount, config.FilterWords) {
				return true
			}
		}
	}

	// Match/Filter line counts
	if len(config.MatchLines) > 0 || len(config.FilterLines) > 0 {
		lineCount := countLines(bodyStr)
		if len(config.MatchLines) > 0 {
			if !countInRanges(lineCount, config.MatchLines) {
				return true
			}
		}
		if len(config.FilterLines) > 0 {
			if countInRanges(lineCount, config.FilterLines) {
				return true
			}
		}
	}

	return false
}

func ShouldFilterRedirect(res *DirResult, config *ScanConfig) bool {
	if res.Redirect == "" {
		return false
	}
	if config.ExcludeRedirectCompiled != nil {
		if config.ExcludeRedirectCompiled.MatchString(res.Redirect) {
			return true
		}
	}
	return false
}

func ShouldFilterHeaders(headerStr string, config *ScanConfig) bool {
	if len(config.MatchHeader) == 0 && len(config.FilterHeader) == 0 {
		return false
	}
	headerLower := strings.ToLower(headerStr)

	for _, mh := range config.MatchHeader {
		mh = strings.ToLower(mh)
		if !strings.Contains(headerLower, mh) {
			return true
		}
	}

	for _, fh := range config.FilterHeader {
		fh = strings.ToLower(fh)
		if strings.Contains(headerLower, fh) {
			return true
		}
	}

	return false
}

func statusInList(status int, list []int) bool {
	for _, s := range list {
		if s == status {
			return true
		}
		if statusIsInRange(status, s) {
			return true
		}
	}
	return false
}

func statusIsInRange(status int, rangeCode int) bool {
	// Range format: 200-399 => we encode as 200399, 300 => single code
	if rangeCode > 10000 {
		min := rangeCode / 1000
		max := rangeCode % 10000
		return status >= min && status <= max
	}
	return false
}

func checkExcludeSizes(size int64, sizes []string) bool {
	for _, s := range sizes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		parsed := parseSize(s)
		if parsed >= 0 && size == parsed {
			return true
		}
	}
	return false
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return -1
	}

	multiplier := int64(1)
	suffix := ""
	if strings.HasSuffix(s, "KB") || strings.HasSuffix(s, "kb") {
		multiplier = 1024
		suffix = s[len(s)-2:]
	} else if strings.HasSuffix(s, "MB") || strings.HasSuffix(s, "mb") {
		multiplier = 1024 * 1024
		suffix = s[len(s)-2:]
	} else if strings.HasSuffix(s, "GB") || strings.HasSuffix(s, "gb") {
		multiplier = 1024 * 1024 * 1024
		suffix = s[len(s)-2:]
	} else if strings.HasSuffix(s, "B") || strings.HasSuffix(s, "b") {
		multiplier = 1
		suffix = s[len(s)-1:]
	}

	numStr := s
	if suffix != "" {
		numStr = strings.TrimSuffix(s, suffix)
	}

	num, err := strconv.ParseInt(strings.TrimSpace(numStr), 10, 64)
	if err != nil {
		return -1
	}
	return num * multiplier
}

func sizeInRanges(size int64, ranges []SizeRange) bool {
	for _, r := range ranges {
		if uint64(size) >= r.Min && uint64(size) <= r.Max {
			return true
		}
	}
	return false
}

func countInRanges(count int, ranges []SizeRange) bool {
	for _, r := range ranges {
		if uint64(count) >= r.Min && uint64(count) <= r.Max {
			return true
		}
	}
	return false
}

func countWords(s string) int {
	return len(strings.Fields(s))
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

func LoadBlacklists(dbDir string) map[int][]string {
	blacklists := make(map[int][]string)
	err := filepath.Walk(dbDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), "_blacklist.txt") {
			return nil
		}
		name := info.Name()
		parts := strings.Split(name, "_")
		if len(parts) < 1 {
			return nil
		}
		statusCode, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil
		}
		paths, err := LoadWordlist(path)
		if err != nil {
			return nil
		}
		blacklists[statusCode] = paths
		return nil
	})
	if err != nil {
		return nil
	}
	return blacklists
}

func parseSizeRange(s string) (SizeRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return SizeRange{}, fmt.Errorf("empty range")
	}

	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		min, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
		max, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
		if err1 != nil || err2 != nil {
			return SizeRange{}, fmt.Errorf("invalid range: %s", s)
		}
		return SizeRange{Min: min, Max: max}, nil
	}

	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return SizeRange{}, err
	}
	return SizeRange{Min: val, Max: val}, nil
}

func parseStatusRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("empty range")
	}

	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		min, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		max, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("invalid range: %s", s)
		}
		return min, max, nil
	}

	val, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, err
	}
	return val, val, nil
}

func parseStatusList(s string) []int {
	if s == "" {
		return nil
	}
	var result []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			min, max, err := parseStatusRange(part)
			if err != nil {
				continue
			}
			for i := min; i <= max; i++ {
				result = append(result, i)
			}
		} else {
			val, err := strconv.Atoi(part)
			if err != nil {
				continue
			}
			result = append(result, val)
		}
	}
	return result
}

func parseSizeRangeList(s string) []SizeRange {
	if s == "" {
		return nil
	}
	var result []SizeRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		r, err := parseSizeRange(part)
		if err != nil {
			// Try as size with KB/MB suffix
			size := parseSize(part)
			if size >= 0 {
				result = append(result, SizeRange{Min: uint64(size), Max: uint64(size)})
			}
			continue
		}
		result = append(result, r)
	}
	return result
}
