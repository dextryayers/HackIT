package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	urlFlag := flag.String("u", "", "Target URL")
	flag.Parse()

	if *urlFlag == "" {
		fmt.Println(`{"error": "URL is required"}`)
		os.Exit(1)
	}

	analyzer := NewAnalyzer()
	result := analyzer.Analyze(*urlFlag)

	if result.Error != "" {
		jsonOut, _ := json.Marshal(map[string]string{"error": result.Error})
		fmt.Println(string(jsonOut))
		os.Exit(0)
	}

	jsonOut, _ := json.Marshal(result)
	fmt.Println(string(jsonOut))
}
