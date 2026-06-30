package main

import (
	"sort"
	"strings"
)

type EngineResult struct {
	Engine  string
	Results []PortResult
}

type portEntries struct {
	entries []enginePortEntry
}

type enginePortEntry struct {
	Engine string
	Result PortResult
}

func MergeResults(engines []string, inputs ...[]PortResult) []PortResult {
	if len(inputs) == 0 {
		return nil
	}
	if len(inputs) == 1 {
		return inputs[0]
	}

	byPort := make(map[int]*portEntries)

	for ei, input := range inputs {
		engineName := "unknown"
		if ei < len(engines) {
			engineName = engines[ei]
		}
		for _, r := range input {
			if r.Port <= 0 {
				continue
			}
			if byPort[r.Port] == nil {
				byPort[r.Port] = &portEntries{}
			}
			byPort[r.Port].entries = append(byPort[r.Port].entries, enginePortEntry{
				Engine: engineName,
				Result: r,
			})
		}
	}

	var merged []PortResult
	for port, pe := range byPort {
		mr := mergeSinglePort(port, pe.entries)
		merged = append(merged, mr)
	}

	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Port < merged[j].Port
	})

	return merged
}

func mergeSinglePort(port int, entries []enginePortEntry) PortResult {
	base := PortResult{Port: port, State: "closed"}

	openCount := 0
	filteredCount := 0
	closedCount := 0
	totalVotes := len(entries)

	for _, e := range entries {
		switch e.Result.State {
		case "open":
			openCount++
		case "filtered", "open|filtered":
			filteredCount++
		case "closed":
			closedCount++
		}
	}

	switch {
	case openCount >= 2:
		base.State = "open"
	case openCount == 1 && totalVotes > 1:
		if filteredCount > 0 || closedCount > 0 {
			base.State = "filtered"
		} else {
			base.State = "open"
		}
	case filteredCount > closedCount:
		base.State = "filtered"
	case closedCount > 0:
		base.State = "closed"
	case openCount == 1:
		base.State = "open"
	}

	var openEntries []enginePortEntry
	for _, e := range entries {
		if e.Result.State == "open" {
			openEntries = append(openEntries, e)
		}
	}

	candidates := openEntries
	if len(candidates) == 0 {
		candidates = entries
	}

	base.Service = pickBestService(candidates)
	base.Banner = pickBestBanner(candidates)
	base.Version = pickBestVersion(candidates, base.Service)
	base.Protocol = pickBestProtocol(candidates)

	vulnSet := make(map[string]bool)
	for _, e := range entries {
		for _, v := range e.Result.Vulnerabilities {
			if !vulnSet[v] {
				vulnSet[v] = true
				base.Vulnerabilities = append(base.Vulnerabilities, v)
			}
		}
	}

	scriptSet := make(map[string]bool)
	for _, e := range entries {
		for _, s := range e.Result.Scripts {
			if !scriptSet[s] {
				scriptSet[s] = true
				base.Scripts = append(base.Scripts, s)
			}
		}
	}

	for _, e := range entries {
		if e.Result.DeepAnalysis != "" {
			if base.DeepAnalysis == "" {
				base.DeepAnalysis = e.Result.DeepAnalysis
			} else if !strings.Contains(base.DeepAnalysis, e.Result.DeepAnalysis) {
				base.DeepAnalysis += " | " + e.Result.DeepAnalysis
			}
		}
		if e.Result.RiskScore > base.RiskScore {
			base.RiskScore = e.Result.RiskScore
		}
		if len(e.Result.CPEList) > 0 {
			base.CPEList = append(base.CPEList, e.Result.CPEList...)
		}
		if base.Reason == "" && e.Result.Reason != "" {
			base.Reason = e.Result.Reason
		}
	}

	base.CPEList = uniqueStrings(base.CPEList)

	return base
}

func pickBestService(entries []enginePortEntry) string {
	preferred := []string{"http", "https", "ssh", "ftp", "smtp", "dns", "mysql", "postgresql", "redis", "mongodb"}
	engineRank := map[string]int{"cpp": 0, "rust": 1, "c": 2, "go": 3}

	best := ""
	bestRank := 999

	for _, e := range entries {
		svc := strings.TrimSpace(e.Result.Service)
		if svc == "" || svc == "unknown" || svc == "UNKNOWN" {
			continue
		}
		svcLower := strings.ToLower(svc)
		rank := 10

		for i, pref := range preferred {
			if svcLower == pref || strings.Contains(svcLower, pref) {
				rank = i
				break
			}
		}

		if er, ok := engineRank[e.Engine]; ok {
			rank = rank*5 + er
		}

		if rank < bestRank || (rank == bestRank && len(svc) > len(best)) {
			bestRank = rank
			best = svc
		}
	}

	if best == "" {
		for _, e := range entries {
			return lookupServiceName(e.Result.Port)
		}
	}

	return best
}

func pickBestBanner(entries []enginePortEntry) string {
	best := ""
	for _, e := range entries {
		b := strings.TrimSpace(e.Result.Banner)
		if len(b) > len(best) {
			best = b
		}
	}
	return best
}

func pickBestVersion(entries []enginePortEntry, service string) string {
	best := ""
	for _, e := range entries {
		v := strings.TrimSpace(e.Result.Version)
		if v == "" {
			continue
		}
		if best == "" || len(v) > len(best) {
			best = v
		}
	}
	return best
}

func pickBestProtocol(entries []enginePortEntry) string {
	for _, e := range entries {
		if e.Result.Protocol == "tcp" {
			return "tcp"
		}
	}
	for _, e := range entries {
		if e.Result.Protocol != "" {
			return e.Result.Protocol
		}
	}
	return "tcp"
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
