package main

import (
	"bufio"
	"os"
	"strings"
)

func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	return words, scanner.Err()
}

func GenerateURLs(baseURL string, words []string, exts []string) []string {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	var urls []string
	for _, w := range words {
		// Base path
		urls = append(urls, baseURL+w)
		
		// Extensions
		for _, ext := range exts {
			ext = strings.TrimPrefix(ext, ".")
			urls = append(urls, baseURL+w+"."+ext)
		}
	}
	return urls
}
