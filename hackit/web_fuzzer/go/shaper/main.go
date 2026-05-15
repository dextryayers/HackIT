package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type ShapedTarget struct {
	URL      string `json:"url"`
	WAF      string `json:"waf"`
	Priority int    `json:"priority"`
}

func ShapeIntelligence(urls []string) []ShapedTarget {
	var shaped []ShapedTarget
	fmt.Printf("[*] SHAPER: Analyzing %d targets for prioritization...\n", len(urls))
	
	for _, u := range urls {
		// Perform a quick HEAD request for WAF detection (simplified for this example)
		// We'll use our existing CheckWAF logic
		waf := "None" 
		priority := 5 // Default priority
		
		if waf != "None" {
			priority = 1 // Lower priority for WAF protected
		}
		
		shaped = append(shaped, ShapedTarget{
			URL:      u,
			WAF:      waf,
			Priority: priority,
		})
	}
	return shaped
}

func main() {
	if len(os.Args) < 2 {
		return
	}
	
	// In a real pipeline, we'd read from stdin or a file
	var rawURLs []string
	json.Unmarshal([]byte(os.Args[1]), &rawURLs)
	
	results := ShapeIntelligence(rawURLs)
	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}
