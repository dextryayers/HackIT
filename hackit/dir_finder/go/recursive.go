package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

func RunRecursiveScan(config *ScanConfig, initialResults []DirResult) ([]DirResult, *ScanStats) {
	if !config.Recursive && !config.DeepRecursive && !config.ForceRecursive {
		return nil, nil
	}

	allResults := make([]DirResult, 0)
	allResults = append(allResults, initialResults...)

	totalStats := &ScanStats{
		StartTime: time.Now(),
	}

	maxDepth := config.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}

	dirsToScan := collectDirectories(initialResults, config)
	scannedDirs := make(map[string]bool)

	for depth := 1; depth <= maxDepth && len(dirsToScan) > 0; depth++ {
		var nextDirs []string
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, config.Threads)

		client := CreateClient(config)
		uaList := []string{}
		if config.RandomAgent {
			uaList = LoadUserAgents(findDBDir())
		}

		for _, dirPath := range dirsToScan {
			if scannedDirs[dirPath] {
				continue
			}
			scannedDirs[dirPath] = true

			wg.Add(1)
			sem <- struct{}{}

			go func(dir string) {
				defer wg.Done()
				defer func() { <-sem }()

				recursivePaths := generateRecursivePaths(config, dir, depth)

				for _, p := range recursivePaths {
					sr := scanPath(config, client, p, uaList)
					if sr != nil && sr.res != nil {
						sr.res.Depth = depth
						mu.Lock()
						filtered := ShouldFilter(sr.res, config) ||
							ShouldFilterBody([]byte(sr.body), sr.res, config) ||
							ShouldFilterRedirect(sr.res, config) ||
							ShouldFilterHeaders(sr.header, config)
						if !filtered {
							allResults = append(allResults, *sr.res)
							totalStats.Found++
						}
						mu.Unlock()
						totalStats.TotalRequests++

						if shouldRecurse(sr.res, config) {
							mu.Lock()
							nextDirs = append(nextDirs, sr.res.Path)
							mu.Unlock()
						}
					} else {
						totalStats.Errors++
					}
				}
			}(dirPath)
		}

		wg.Wait()

		dirsToScan = nextDirs

		fmt.Fprintf(color.Output, "%s Recursive depth %d/%d complete. Found: %d\n",
			color.CyanString("[*]"), depth, maxDepth, totalStats.Found)
	}

	totalStats.EndTime = time.Now()
	return allResults, totalStats
}

func collectDirectories(results []DirResult, config *ScanConfig) []string {
	dirs := make(map[string]bool)
	for _, r := range results {
		if shouldRecurse(&r, config) {
			dirs[r.Path] = true
		}
	}
	result := make([]string, 0, len(dirs))
	for d := range dirs {
		result = append(result, d)
	}
	return result
}

func shouldRecurse(res *DirResult, config *ScanConfig) bool {
	if !config.Recursive && !config.ForceRecursive {
		return false
	}
	if res.Status < 200 || res.Status >= 400 {
		return false
	}
	if len(config.RecursionStatus) > 0 {
		if !statusInList(res.Status, config.RecursionStatus) {
			return false
		}
	}
	if config.Recursive && !config.ForceRecursive {
		return strings.HasSuffix(res.Path, "/")
	}
	if config.ForceRecursive {
		return true
	}
	return false
}

func generateRecursivePaths(config *ScanConfig, baseDir string, currentDepth int) []string {
	baseDir = strings.TrimSuffix(baseDir, "/")
	if baseDir != "" {
		baseDir += "/"
	}

	var paths []string

	if config.DeepRecursive && currentDepth == 1 {
		parts := strings.Split(strings.Trim(baseDir, "/"), "/")
		accum := ""
		for _, part := range parts {
			if part == "" {
				continue
			}
			accum += part + "/"
			if accum != baseDir {
				path := strings.TrimPrefix(accum, "/")
				for _, origPath := range config.Paths {
					paths = append(paths, path+origPath)
				}
			}
		}
	} else {
		for _, origPath := range config.Paths {
			paths = append(paths, baseDir+origPath)
		}
	}

	if len(config.ExcludeSubdirs) > 0 {
		var filtered []string
		for _, p := range paths {
			excluded := false
			for _, ex := range config.ExcludeSubdirs {
				if strings.Contains(p, "/"+strings.Trim(ex, "/")+"/") {
					excluded = true
					break
				}
			}
			if !excluded {
				filtered = append(filtered, p)
			}
		}
		paths = filtered
	}

	return paths
}
