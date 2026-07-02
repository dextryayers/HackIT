package main

import (
	"path/filepath"
	"strings"
)

type RecursionPlan struct {
	Enabled      bool
	MaxDepth     int
	Strategy     string
	StatusCodes  []int
	Directories  []string
	ExcludeDirs  []string
	Level        int
}

func BuildRecursionPlan(config *ScanConfig) RecursionPlan {
	plan := RecursionPlan{
		Enabled:     config.Recursive || config.DeepRecursive || config.ForceRecursive,
		MaxDepth:    config.MaxDepth,
		StatusCodes: config.RecursionStatus,
		Directories: config.Subdirs,
		ExcludeDirs: config.ExcludeSubdirs,
		Level:       0,
	}

	switch {
	case config.DeepRecursive:
		plan.Strategy = "deep"
	case config.ForceRecursive:
		plan.Strategy = "force"
	default:
		plan.Strategy = "standard"
	}

	if len(plan.StatusCodes) == 0 {
		plan.StatusCodes = []int{301, 302, 200, 403}
	}

	return plan
}

func ShouldRecurse(result *DirResult, plan RecursionPlan) bool {
	if !plan.Enabled {
		return false
	}
	if plan.Level >= plan.MaxDepth {
		return false
	}
	if plan.Strategy == "force" {
		return true
	}
	if plan.Strategy == "deep" && result.Status == 200 {
		return true
	}
	for _, code := range plan.StatusCodes {
		if result.Status == code {
			return true
		}
	}
	return false
}

func ExpandSubdirs(paths []string, subdirs []string) []string {
	if len(subdirs) == 0 {
		return paths
	}
	var expanded []string
	for _, p := range paths {
		expanded = append(expanded, p)
		for _, sd := range subdirs {
			sd = strings.Trim(sd, "/")
			if sd != "" {
				expanded = append(expanded, sd+"/"+p)
			}
		}
	}
	return Deduplicate(expanded)
}

func FilterExcludedSubdirs(paths []string, excluded []string) []string {
	if len(excluded) == 0 {
		return paths
	}
	var result []string
	for _, p := range paths {
		skip := false
		for _, ex := range excluded {
			ex = strings.Trim(ex, "/")
			dir := filepath.Dir(p)
			if dir == ex || strings.HasPrefix(dir, ex+"/") {
				skip = true
				break
			}
		}
		if !skip {
			result = append(result, p)
		}
	}
	return result
}

