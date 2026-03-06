package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadWordlist reads paths from a file
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

// LoadAllPayloads scans the db directory recursively and loads all .txt files
func LoadAllPayloads(dbDir string) ([]string, error) {
	var allPaths []string

	err := filepath.Walk(dbDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip user-agents.txt as it's not a directory wordlist
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".txt") && info.Name() != "user-agents.txt" {
			paths, err := LoadWordlist(path)
			if err == nil {
				allPaths = append(allPaths, paths...)
			}
		}
		return nil
	})

	return allPaths, err
}

// FormatSize converts bytes to human readable format
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
	return fmt.Sprintf("%dMB", bytes/(1024*1024))
}
