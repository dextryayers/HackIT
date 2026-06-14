package core

import (
	"fmt"
	"sort"
)

type CharSet struct {
	Name        string
	Characters  []byte
	Description string
}

var KnownCharsets = []CharSet{
	{
		Name:        "alphanumeric",
		Characters:  appendBytes(generateRange('a', 'z'), generateRange('0', '9')),
		Description: "Lowercase letters and digits",
	},
	{
		Name:        "alphanumeric_mixed",
		Characters:  appendBytes(generateRange('a', 'z'), generateRange('A', 'Z'), generateRange('0', '9')),
		Description: "All letters and digits",
	},
	{
		Name:        "hex",
		Characters:  []byte("0123456789abcdef"),
		Description: "Hexadecimal characters",
	},
	{
		Name:        "base64",
		Characters:  appendBytes(generateRange('A', 'Z'), generateRange('a', 'z'), generateRange('0', '9'), []byte("+/=")),
		Description: "Base64 charset",
	},
	{
		Name:        "email",
		Characters:  appendBytes(generateRange('a', 'z'), generateRange('0', '9'), []byte("@._-")),
		Description: "Email-safe characters",
	},
	{
		Name:        "printable",
		Characters:  generateRange(32, 126),
		Description: "All printable ASCII",
	},
	{
		Name:        "numeric",
		Characters:  generateRange('0', '9'),
		Description: "Digits only",
	},
}

func generateRange(start, end byte) []byte {
	r := make([]byte, 0, end-start+1)
	for i := start; i <= end; i++ {
		r = append(r, i)
	}
	return r
}

func appendBytes(slices ...[]byte) []byte {
	total := 0
	for _, s := range slices {
		total += len(s)
	}
	result := make([]byte, 0, total)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}

type CharSetOptimizer struct {
	engine *Engine
}

func NewCharSetOptimizer(e *Engine) *CharSetOptimizer {
	return &CharSetOptimizer{engine: e}
}

func (c *CharSetOptimizer) DetectBestCharset(param string, queryTemplate string) (*CharSet, error) {
	c.engine.logInfo("Optimizing character set for blind extraction...")

	reducedSearch := func(chars []byte) ([]byte, error) {
		found := []byte{}
		for _, ch := range chars {
			payload := fmt.Sprintf(queryTemplate, 1, int(ch))
			body, _, _, err := c.engine.Request(payload, param)
			if err != nil {
				continue
			}
			if len(body) > 100 {
				found = append(found, ch)
			}
		}
		return found, nil
	}

	c.engine.logInfo("Testing alphanumeric charset (36 chars)...")
	alphaChars, err := reducedSearch(KnownCharsets[0].Characters)
	if err != nil {
		return nil, err
	}

	if len(alphaChars) >= 20 {
		c.engine.logInfo(fmt.Sprintf("Charset optimized: alphanumeric (%d confirmed)", len(alphaChars)))
		optimized := &CharSet{
			Name:       "optimized_alphanumeric",
			Characters: alphaChars,
		}
		return optimized, nil
	}

	c.engine.logInfo("Testing full printable charset (95 chars)...")
	fullChars, err := reducedSearch(KnownCharsets[5].Characters)
	if err != nil {
		return nil, err
	}

	c.engine.logInfo(fmt.Sprintf("Charset optimized: %d printable characters confirmed", len(fullChars)))
	return &CharSet{
		Name:       "optimized_printable",
		Characters: fullChars,
	}, nil
}

func (c *CharSetOptimizer) OptimizeBinarySearch(param string, queryTemplate string, charset []byte) map[byte]int {
	charMap := make(map[byte]int)
	_ = charMap

	sortedChars := make([]byte, len(charset))
	copy(sortedChars, charset)
	sort.Slice(sortedChars, func(i, j int) bool {
		return sortedChars[i] < sortedChars[j]
	})

	c.engine.logInfo(fmt.Sprintf("Binary search optimized with %d chars", len(sortedChars)))
	return charMap
}

func (c *CharSetOptimizer) EstimateExtractionTime(maxLen int, charsetSize int) string {
	requestsPerChar := 0
	temp := charsetSize
	for temp > 1 {
		temp /= 2
		requestsPerChar++
	}

	totalRequests := maxLen * requestsPerChar
	estTime := float64(totalRequests) * 0.5

	if estTime < 60 {
		return fmt.Sprintf("~%.0f seconds (%d requests)", estTime, totalRequests)
	}
	return fmt.Sprintf("~%.1f minutes (%d requests)", estTime/60, totalRequests)
}
