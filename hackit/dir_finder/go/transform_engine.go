package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

type TransformStats struct {
	Original     int
	AfterExt     int
	AfterCase    int
	AfterAffix   int
	Total        int
}

func ProcessPathTransforms(paths []string, config *ScanConfig) []string {
	result := paths
	stats := TransformStats{Original: len(paths)}

	result = applyExtensions(result, config)
	stats.AfterExt = len(result)

	result = applyCaseTransforms(result, config)
	stats.AfterCase = len(result)

	result = applyAffixes(result, config)
	stats.AfterAffix = len(result)

	result = Deduplicate(result)
	stats.Total = len(result)

	if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Transforms: %d -> %d (ext=%d case=%d affix=%d)\n",
			color.GreenString("[+]"), stats.Original, stats.Total,
			stats.AfterExt-stats.Original, stats.AfterCase-stats.AfterExt,
			stats.AfterAffix-stats.AfterCase)
	}

	return result
}

func applyExtensions(paths []string, config *ScanConfig) []string {
	if len(config.Extensions) == 0 {
		return paths
	}
	var result []string
	for _, p := range paths {
		result = append(result, p)
		hasExt := strings.Contains(p, ".")
		force := config.ForceExtensions

		if config.OverwriteExtensions || (!hasExt && force) {
			for _, ext := range config.Extensions {
				ext = strings.TrimPrefix(ext, ".")
				result = append(result, p+"."+ext)
			}
		} else if !hasExt {
			for _, ext := range config.Extensions {
				ext = strings.TrimPrefix(ext, ".")
				result = append(result, p+"."+ext)
			}
		}
	}
	return result
}

func applyCaseTransforms(paths []string, config *ScanConfig) []string {
	var result []string
	for _, p := range paths {
		result = append(result, p)
		if config.Uppercase {
			result = append(result, strings.ToUpper(p))
		}
		if config.Lowercase {
			result = append(result, strings.ToLower(p))
		}
		if config.Capital {
			if len(p) > 0 {
				result = append(result, strings.ToUpper(p[:1])+p[1:])
			}
		}
	}
	return result
}

func applyAffixes(paths []string, config *ScanConfig) []string {
	if len(config.Prefixes) == 0 && len(config.Suffixes) == 0 {
		return paths
	}
	var result []string
	for _, p := range paths {
		result = append(result, p)
		for _, prefix := range config.Prefixes {
			result = append(result, prefix+p)
		}
		for _, suffix := range config.Suffixes {
			result = append(result, p+suffix)
		}
	}
	return result
}

func FilterExcludedExtensions(paths []string, excluded []string) []string {
	if len(excluded) == 0 {
		return paths
	}
	var result []string
	for _, p := range paths {
		keep := true
		for _, ext := range excluded {
			ext = strings.TrimPrefix(ext, ".")
			if strings.HasSuffix(p, "."+ext) {
				keep = false
				break
			}
		}
		if keep {
			result = append(result, p)
		}
	}
	return result
}
