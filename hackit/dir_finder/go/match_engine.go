package main

import (
	"regexp"
	"strings"
)

type MatchResult struct {
	Matched   bool
	Filtered  bool
	Reason    string
}

func MatchResponseAdvanced(res *DirResult, body string, header string, config *ScanConfig) MatchResult {
	mr := MatchResult{Matched: true}

	// --- MATCH rules (positive: must match to pass) ---
	if config.MatchStatus != nil {
		if !statusInList(res.Status, config.MatchStatus) {
			return MatchResult{false, true, "match-status"}
		}
	}

	if config.MatchSize != nil {
		if !sizeInRangesUint(uint64(res.Size), config.MatchSize) {
			return MatchResult{false, true, "match-size"}
		}
	}

	if config.MatchWords != nil {
		if !sizeInRangesUint(uint64(res.Words), config.MatchWords) {
			return MatchResult{false, true, "match-words"}
		}
	}

	if config.MatchLines != nil {
		if !sizeInRangesUint(uint64(res.Lines), config.MatchLines) {
			return MatchResult{false, true, "match-lines"}
		}
	}

	if config.MatchRegex != "" {
		matched, err := regexp.MatchString(config.MatchRegex, body)
		if err != nil || !matched {
			return MatchResult{false, true, "match-regex"}
		}
	}

	if config.MatchHeader != nil {
		found := false
		for _, mh := range config.MatchHeader {
			if strings.Contains(header, mh) {
				found = true
				break
			}
		}
		if !found {
			return MatchResult{false, true, "match-header"}
		}
	}

	// --- FILTER rules (negative: skip if matches) ---
	if config.FilterStatus != nil {
		if statusInList(res.Status, config.FilterStatus) {
			return MatchResult{true, true, "filter-status"}
		}
	}

	if config.FilterSize != nil {
		if sizeInRangesUint(uint64(res.Size), config.FilterSize) {
			return MatchResult{true, true, "filter-size"}
		}
	}

	if config.FilterWords != nil {
		if sizeInRangesUint(uint64(res.Words), config.FilterWords) {
			return MatchResult{true, true, "filter-words"}
		}
	}

	if config.FilterLines != nil {
		if sizeInRangesUint(uint64(res.Lines), config.FilterLines) {
			return MatchResult{true, true, "filter-lines"}
		}
	}

	if config.FilterRegex != "" {
		matched, err := regexp.MatchString(config.FilterRegex, body)
		if err == nil && matched {
			return MatchResult{true, true, "filter-regex"}
		}
	}

	if config.FilterHeader != nil {
		for _, fh := range config.FilterHeader {
			if strings.Contains(header, fh) {
				return MatchResult{true, true, "filter-header"}
			}
		}
	}

	return mr
}

func sizeInRangesUint(val uint64, ranges []SizeRange) bool {
	for _, r := range ranges {
		if r.Min == 0 && r.Max == 0 {
			if val == 0 {
				return true
			}
			continue
		}
		if r.Max == 0 {
			if val >= r.Min {
				return true
			}
			continue
		}
		if val >= r.Min && val <= r.Max {
			return true
		}
	}
	return false
}


