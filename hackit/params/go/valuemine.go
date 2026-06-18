package main

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	reEnumValue    = regexp.MustCompile(`^(asc|desc|ascending|descending|enabled|disabled|active|inactive|on|off|yes|no|true|false|1|0)$`)
	reSortValue    = regexp.MustCompile(`^(asc|desc|ascending|descending)$`)
	reFormatValue  = regexp.MustCompile(`^(json|xml|html|text|csv|yaml|yml|plain|markdown|md|pdf|png|jpg|svg|webp|ico)$`)
	reLocaleValue  = regexp.MustCompile(`^[a-z]{2}([_-][A-Z]{2})?$`)
	reLanguageOnly = regexp.MustCompile(`^[a-z]{2,3}$`)
	reVersionValue = regexp.MustCompile(`^v?\d+\.\d+(\.\d+)?([.-][a-zA-Z0-9]+)?$`)
	reModeValue    = regexp.MustCompile(`^(edit|view|preview|draft|published|archived|deleted|trash|live|dev|staging|production|prod|test|debug|release)$`)
	reFlagValue    = regexp.MustCompile(`^(0|1|true|false|on|off|yes|no|enabled|disabled)$`)
	reCursorValue  = regexp.MustCompile(`^[A-Za-z0-9_-]{10,}$`)
	rePhoneValue   = regexp.MustCompile(`^\+?\d{7,15}$`)
	reIPValue      = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	reColorValue   = regexp.MustCompile(`^#[0-9a-fA-F]{3,8}$`)
	reCurrencyVal  = regexp.MustCompile(`^[$]\d+(\.\d{1,2})?$|^\d+(\.\d{1,2})?[$]$`)
	rePercentVal   = regexp.MustCompile(`^\d+(\.\d+)?%$`)
)

type paramValueProfile struct {
	Param      string
	Samples    map[string]int
	Types      map[string]int
	Total      int
	Confidence float64
}

func mineParamValues(name string, values []string) *ValueMine {
	if len(values) == 0 {
		return nil
	}

	uniqueVals := uniqueStrings(values)
	if len(uniqueVals) == 0 {
		return nil
	}

	// Try to match against known patterns
	matched := ""

	// Single unique value - probably an ID or token
	if len(uniqueVals) == 1 {
		v := uniqueVals[0]
		switch {
		case reNumericPath.MatchString(v):
			matched = "single_id"
		case reUUIDPath.MatchString(strings.ToLower(v)):
			matched = "single_uuid"
		case reHexPath.MatchString(v):
			matched = "single_hash"
		case reURL.MatchString(strings.ToLower(v)):
			matched = "single_url"
		case reEmail.MatchString(strings.ToLower(v)):
			matched = "single_email"
		case hasMixedCase(v) && len(v) > 15:
			matched = "single_token"
		default:
			matched = "single_value"
		}
		return &ValueMine{
			Param:     name,
			Pattern:   matched,
			Examples:  []string{truncateString(v, 40)},
			Confidence: "medium",
		}
	}

	// Multiple unique values - look for patterns
	allEnum := true
	allNumeric := true
	allUUID := true
	for _, v := range uniqueVals {
		if !reEnumValue.MatchString(strings.ToLower(v)) {
			allEnum = false
		}
		if !reNumericPath.MatchString(v) {
			allNumeric = false
		}
		if !reUUIDPath.MatchString(strings.ToLower(v)) {
			allUUID = false
		}
	}

	if allEnum {
		sort.Strings(uniqueVals)
		examples := uniqueVals
		if len(examples) > 5 {
			examples = examples[:5]
		}
		return &ValueMine{
			Param:     name,
			Pattern:   "enum",
			Examples:  examples,
			Confidence: "high",
		}
	}

	if allNumeric {
		sorted := sortedAsInts(uniqueVals)
		if len(sorted) >= 2 {
			min, max := sorted[0], sorted[len(sorted)-1]
			if max-min <= int64(len(sorted))*2 {
				return &ValueMine{
					Param:     name,
					Pattern:   "sequential_id",
					Examples:  []string{strconv.FormatInt(min, 10), strconv.FormatInt(max, 10)},
					Confidence: "high",
				}
			}
		}
		return &ValueMine{
			Param:     name,
			Pattern:   "numeric_range",
			Examples:  []string{uniqueVals[0], uniqueVals[len(uniqueVals)-1]},
			Confidence: "medium",
		}
	}

	if allUUID {
		return &ValueMine{
			Param:     name,
			Pattern:   "uuid_set",
			Examples:  []string{uniqueVals[0], uniqueVals[1%len(uniqueVals)]},
			Confidence: "high",
		}
	}

	// Check if all values follow a consistent format
	allSort := true
	allFormat := true
	allLocale := true
	allVersion := true
	allMode := true
	for _, v := range uniqueVals {
		if !reSortValue.MatchString(strings.ToLower(v)) {
			allSort = false
		}
		if !reFormatValue.MatchString(strings.ToLower(v)) {
			allFormat = false
		}
		if !reLocaleValue.MatchString(v) {
			allLocale = false
		}
		if !reVersionValue.MatchString(strings.ToLower(v)) {
			allVersion = false
		}
		if !reModeValue.MatchString(strings.ToLower(v)) {
			allMode = false
		}
	}

	switch {
	case allSort:
		matched = "sort_order"
	case allFormat:
		matched = "format_enum"
	case allLocale:
		matched = "locale"
	case allVersion:
		matched = "version"
	case allMode:
		matched = "mode"
	default:
		// Multi-pattern
		patterns := countPatterns(uniqueVals)
		if len(patterns) > 0 {
			matched = "mixed_" + patterns[0]
		} else {
			matched = "variable"
		}
	}

	return &ValueMine{
		Param:     name,
		Pattern:   matched,
		Examples:  uniqueVals[:minInt(len(uniqueVals), 3)],
		Confidence: "medium",
	}
}

func countPatterns(values []string) []string {
	patternCount := make(map[string]int)
	for _, v := range values {
		switch {
		case reNumericPath.MatchString(v):
			patternCount["numeric"]++
		case reUUIDPath.MatchString(strings.ToLower(v)):
			patternCount["uuid"]++
		case reHexPath.MatchString(v):
			patternCount["hex"]++
		case reEnumValue.MatchString(strings.ToLower(v)):
			patternCount["enum"]++
		case reFlagValue.MatchString(strings.ToLower(v)):
			patternCount["flag"]++
		case reLocaleValue.MatchString(v):
			patternCount["locale"]++
		case reVersionValue.MatchString(strings.ToLower(v)):
			patternCount["version"]++
		case reFormatValue.MatchString(strings.ToLower(v)):
			patternCount["format"]++
		case reCursorValue.MatchString(v):
			patternCount["cursor"]++
		default:
			patternCount["string"]++
		}
	}

	// Sort patterns by count desc
	type pc struct {
		name  string
		count int
	}
	var sorted []pc
	for k, v := range patternCount {
		sorted = append(sorted, pc{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	var result []string
	for _, p := range sorted {
		result = append(result, p.name)
	}
	return result
}

func sortedAsInts(strs []string) []int64 {
	var ints []int64
	for _, s := range strs {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			ints = append(ints, n)
		}
	}
	sort.Slice(ints, func(i, j int) bool { return ints[i] < ints[j] })
	return ints
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func findValueMineFindings(allResults []DiscoResult) ([]Finding, []ValueMine) {
	// Group values by param name
	paramValues := make(map[string][]string)
	for _, r := range allResults {
		for name, val := range r.Params {
			if val != "" {
				paramValues[name] = append(paramValues[name], val)
			}
		}
	}

	var findings []Finding
	var mines []ValueMine

	for name, values := range paramValues {
		mine := mineParamValues(name, values)
		if mine == nil {
			continue
		}
		mines = append(mines, *mine)

		// Only emit findings for interesting patterns
		switch mine.Pattern {
		case "enum", "sort_order", "format_enum", "mode", "locale", "version":
			findings = append(findings, Finding{
				Type:        "value_pattern",
				Category:    "Value Pattern: " + mine.Pattern,
				Param:       name,
				Description: "Parameter '" + name + "' values follow " + mine.Pattern + " pattern: " + strings.Join(mine.Examples, ", "),
				Severity:    SeverityLow,
			})
		case "sequential_id":
			findings = append(findings, Finding{
				Type:        "sequential_id",
				Category:    "Sequential ID",
				Param:       name,
				Description: "Sequential numeric IDs in parameter: " + name + " " + strings.Join(mine.Examples, " → "),
				Severity:    SeverityMedium,
			})
		case "single_token":
			findings = append(findings, Finding{
				Type:        "single_token",
				Category:    "Single Token/Key",
				Param:       name,
				Description: "Token-like single value in parameter: " + name + "=" + mine.Examples[0],
				Severity:    SeverityLow,
			})
		}
	}

	return findings, mines
}
