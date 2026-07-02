package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

type SmartFilterConfig struct {
	Enabled      bool
	Threshold    int
	Similarity   int
	AdaptiveRate bool
	ExitOnError  bool
	MaxTime      int
}

type AdaptiveRateController struct {
	Enabled       bool
	CurrentRate   int
	MinRate       int
	MaxRate       int
	ErrorRate     float64
	TotalRequests int
	ErrorCount    int
}

func NewAdaptiveRateController(config *ScanConfig) *AdaptiveRateController {
	return &AdaptiveRateController{
		Enabled:     config.AdaptiveRate,
		CurrentRate: config.Threads,
		MinRate:     1,
		MaxRate:     config.Threads * 2,
	}
}

func (arc *AdaptiveRateController) RecordResult(isErr bool) {
	arc.TotalRequests++
	if isErr {
		arc.ErrorCount++
	}
	arc.ErrorRate = float64(arc.ErrorCount) / float64(maxInt(arc.TotalRequests, 1))

	if arc.Enabled {
		if arc.ErrorRate > 0.3 {
			arc.CurrentRate = maxInt(arc.CurrentRate-1, arc.MinRate)
		} else if arc.ErrorRate < 0.05 && arc.TotalRequests > 10 {
			arc.CurrentRate = minInt(arc.CurrentRate+1, arc.MaxRate)
		}
	}
}

func (arc *AdaptiveRateController) GetRate() int {
	return arc.CurrentRate
}

func (arc *AdaptiveRateController) GetDelay() int {
	if !arc.Enabled {
		return 0
	}
	if arc.ErrorRate > 0.2 {
		return 200
	}
	if arc.ErrorRate > 0.1 {
		return 100
	}
	if arc.ErrorRate > 0.05 {
		return 50
	}
	return 0
}

func SmartFilterResult(res *DirResult, config *ScanConfig, fpFrequency map[string]int) bool {
	if !config.SmartFilter {
		return false
	}

	fpKey := fmt.Sprintf("%s-%d-%d-%d-%d", res.BodyHash, res.Status, res.Size, res.Words, res.Lines)
	fpFrequency[fpKey]++

	if fpFrequency[fpKey] > 10 {
		if fpFrequency[fpKey] == 11 {
			fmt.Fprintf(color.Output, "%s%s Suppressing high-frequency pattern (status=%d size=%s words=%d lines=%d)\n",
				ANSI_CLEAR_LINE, color.YellowString("[!]"),
				res.Status, FormatSize(res.Size), res.Words, res.Lines)
		}
		return true
	}

	return false
}

func CheckResponseSimilarityThreshold(res1, res2 *DirResult, threshold int) bool {
	if threshold <= 0 {
		return false
	}
	similarity := CheckResponseSimilarity(res1, res2)
	return similarity >= threshold
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var soft404Keywords = []string{
	"not found", "error 404", "page not found", "doesn't exist",
	"no results", "nothing found", "404 error", "page unavailable",
	"this page could not be found", "http 404", "not available",
	"content not found", "no such page", "404 not found",
	"the requested url was not found", "page does not exist",
	"halaman tidak ditemukan", "pagina no encontrada",
	"seite nicht gefunden", "page non trouvee",
	"404 - not found", "error 404 - not found",
}

func CheckSoft404(body string, title string) bool {
	bodyLower := strings.ToLower(body)
	titleLower := strings.ToLower(title)
	for _, kw := range soft404Keywords {
		if strings.Contains(bodyLower, kw) || strings.Contains(titleLower, kw) {
			return true
		}
	}
	return false
}
