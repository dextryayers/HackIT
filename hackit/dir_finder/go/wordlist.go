package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func LoadAllPayloads(dbDir string) ([]string, error) {
	var allPaths []string
	err := filepath.Walk(dbDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".txt") && info.Name() != "user-agents.txt" && info.Name() != "generate_wpscan_wordlists.py" {
			paths, err := LoadWordlist(path)
			if err == nil {
				allPaths = append(allPaths, paths...)
			}
		}
		return nil
	})
	return allPaths, err
}

func LoadWordlistByCategory(dbDir string, categories []string) ([]string, error) {
	var allPaths []string
	for _, cat := range categories {
		catDir := filepath.Join(dbDir, "categories", cat)
		if info, err := os.Stat(catDir); err == nil && info.IsDir() {
			paths, err := LoadAllPayloads(catDir)
			if err == nil {
				allPaths = append(allPaths, paths...)
			}
		}
		catFile := filepath.Join(dbDir, "categories", cat+".txt")
		if info, err := os.Stat(catFile); err == nil && !info.IsDir() {
			paths, err := LoadWordlist(catFile)
			if err == nil {
				allPaths = append(allPaths, paths...)
			}
		}
	}
	if len(categories) > 0 && strings.EqualFold(categories[0], "all") {
		return LoadAllPayloads(filepath.Join(dbDir, "categories"))
	}
	if len(categories) > 0 && strings.EqualFold(categories[0], "common") {
		commonPath := filepath.Join(dbDir, "categories", "common.txt")
		if _, err := os.Stat(commonPath); err == nil {
			return LoadWordlist(commonPath)
		}
	}
	return allPaths, nil
}

func Deduplicate(paths []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

func ProcessPaths(paths []string, config *ScanConfig) []string {
	if len(paths) == 0 {
		return paths
	}

	result := make([]string, 0, len(paths)*3)

	for _, p := range paths {
		if p == "" {
			continue
		}

		base := p
		if strings.Contains(base, "%EXT%") && len(config.Extensions) > 0 {
			for _, ext := range config.Extensions {
				ext = strings.TrimPrefix(ext, ".")
				result = append(result, strings.ReplaceAll(base, "%EXT%", ext))
			}
			if !config.ForceExtensions {
				continue
			}
		}

		prefixAdded := false
		for _, prefix := range config.Prefixes {
			result = append(result, prefix+p)
			prefixAdded = true
		}

		suffixAdded := false
		for _, suffix := range config.Suffixes {
			if !strings.HasSuffix(p, "/") {
				result = append(result, p+suffix)
				suffixAdded = true
			}
		}

		if !prefixAdded && !suffixAdded {
			result = append(result, p)
		}

		if config.ForceExtensions && len(config.Extensions) > 0 && !strings.HasSuffix(p, "/") && !strings.Contains(base, "%EXT%") {
			for _, ext := range config.Extensions {
				ext = strings.TrimPrefix(ext, ".")
				result = append(result, p+"."+ext)
			}
		}

		if config.OverwriteExtensions && len(config.Extensions) > 0 {
			ext := pathExt(p)
			if ext != "" {
				baseNoExt := strings.TrimSuffix(p, "."+ext)
				if !isExcludedExtension(ext, config.ExcludeExtensions) {
					for _, newExt := range config.Extensions {
						newExt = strings.TrimPrefix(newExt, ".")
						result = append(result, baseNoExt+"."+newExt)
					}
				}
			}
		}
	}

	if config.Uppercase {
		upper := make([]string, len(result))
		for i, p := range result {
			upper[i] = strings.ToUpper(p)
		}
		result = append(result, upper...)
	}
	if config.Lowercase {
		lower := make([]string, len(result))
		for i, p := range result {
			lower[i] = strings.ToLower(p)
		}
		result = append(result, lower...)
	}
	if config.Capital {
		cap := make([]string, len(result))
		for i, p := range result {
			if len(p) > 0 {
				cap[i] = strings.ToUpper(p[:1]) + p[1:]
			} else {
				cap[i] = p
			}
		}
		result = append(result, cap...)
	}

	return Deduplicate(result)
}

func pathExt(p string) string {
	i := strings.LastIndex(p, ".")
	if i > 0 && !strings.Contains(p[i:], "/") {
		return p[i+1:]
	}
	return ""
}

func isExcludedExtension(ext string, excluded []string) bool {
	for _, e := range excluded {
		if strings.EqualFold(strings.TrimPrefix(e, "."), ext) {
			return true
		}
	}
	return false
}

func FormatSize(bytes int64) string {
	if bytes < 0 {
		return "0B"
	}
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%dKB", bytes/1024)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%dMB", bytes/(1024*1024))
	}
	return fmt.Sprintf("%dGB", bytes/(1024*1024*1024))
}

func LoadUserAgents(dbDir string) []string {
	uaPath := filepath.Join(dbDir, "user-agents.txt")
	if content, err := os.ReadFile(uaPath); err == nil {
		lines := strings.Split(string(content), "\n")
		agents := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				agents = append(agents, line)
			}
		}
		return agents
	}
	return nil
}
