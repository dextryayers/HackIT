package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

type DictionaryStats struct {
	TotalPaths  int
	Categories  []string
	FilesLoaded int
	Source      string
}

func LoadDictionary(config *ScanConfig) ([]string, DictionaryStats) {
	stats := DictionaryStats{}
	foundDB := findDBDir()

	var paths []string
	var err error

	if len(config.WordlistCategories) > 0 {
		paths, err = LoadWordlistByCategory(foundDB, config.WordlistCategories)
		stats.Categories = config.WordlistCategories
		stats.Source = "categories: " + strings.Join(config.WordlistCategories, ", ")
	} else if len(config.Wordlists) > 0 {
		for _, wl := range config.Wordlists {
			p, e := LoadWordlist(wl)
			if e == nil {
				paths = append(paths, p...)
				stats.FilesLoaded++
			}
		}
		stats.Source = "custom: " + strings.Join(config.Wordlists, ", ")
	} else {
		paths, err = LoadAllPayloads(foundDB)
		stats.Source = "auto (all db/)"
	}

	if err != nil || len(paths) == 0 {
		paths = []string{
			".env", ".git/config", "admin", "login", "wp-admin",
			"backup", "config", "robots.txt", "sitemap.xml",
		}
		stats.Source = "fallback defaults"
	}

	stats.TotalPaths = len(paths)
	return paths, stats
}

func LoadCategoryWordlists(dbDir string, categories []string) ([]string, error) {
	var all []string
	for _, cat := range categories {
		cat = strings.TrimSpace(cat)
		catPath := filepath.Join(dbDir, "categories", cat+".txt")
		paths, err := LoadWordlist(catPath)
		if err == nil {
			all = append(all, paths...)
		}
		dirPath := filepath.Join(dbDir, "categories", cat)
		if entries, err := os.ReadDir(dirPath); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
					p, err := LoadWordlist(filepath.Join(dirPath, e.Name()))
					if err == nil {
						all = append(all, p...)
					}
				}
			}
		}
	}
	return Deduplicate(all), nil
}

func PrintDictionaryInfo(stats DictionaryStats) {
	fmt.Fprintf(color.Output, "%s Dictionary: %s\n", color.CyanString("[*]"), stats.Source)
	fmt.Fprintf(color.Output, "%s Total payloads: %d\n", color.GreenString("[+]"), stats.TotalPaths)
	if len(stats.Categories) > 0 {
		fmt.Fprintf(color.Output, "%s Categories: %s\n", color.CyanString("[*]"),
			strings.Join(stats.Categories, ", "))
	}
}
