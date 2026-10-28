package core

import (
	"fmt"
	"strings"
	"time"
)

// StartV2 is the primary scan pipeline. It discovers every injection point,
// confirms a syntactic boundary, identifies the DBMS and then hands control to
// the Explorer for enumeration and extraction.
func (e *Engine) StartV2() []Result {
	points, err := DiscoverInjectionPoints(e.Opts)
	if err != nil {
		e.Log.Warning(fmt.Sprintf("parameter discovery error: %v", err))
		return []Result{{Parameter: "error", Type: "fatal", Payload: fmt.Sprintf("%v", err), DBMS: "", Confidence: 1.0, Details: "No injectable parameters found"}}
	}
	e.Points = points

	first := points[0]
	e.Log.Info(fmt.Sprintf("testing connection to %s", e.Opts.URL))
	baseBody, baseLen, headers, err := e.RequestAt(first, "")
	if err != nil {
		e.Log.Warning(fmt.Sprintf("connection error: %v", err))
		return []Result{{Parameter: "error", Type: "fatal", Payload: fmt.Sprintf("%v", err), DBMS: "", Confidence: 1.0, Details: "Target is unreachable"}}
	}
	e.BaselineBody = baseBody
	e.BaselineLen = baseLen
	e.BaselineTime = e.LastResponseTime
	e.Log.Success(fmt.Sprintf("target is reachable (%d bytes, %v)", baseLen, e.LastResponseTime.Round(time.Millisecond)))

	waf := DetectWAF(headers, baseBody)
	if waf.Detected {
		e.Log.Critical(fmt.Sprintf("WAF/IPS detected: %s", waf.Name))
		if !e.Opts.BypassWAF {
			e.Log.Warning("consider using --tamper or --bypass-waf")
		}
	}

	heuristicDBMS := DetectDBMS(baseBody, headers)
	if heuristicDBMS != "Unknown" {
		e.Log.Info(fmt.Sprintf("heuristic DBMS fingerprint: %s", heuristicDBMS))
	}

	var results []Result
	for _, point := range points {
		e.Log.Info(fmt.Sprintf("testing %s parameter '%s'", point.Location, point.Name))
		boundary, technique, ok := e.DetectBoundary(point, baseBody)
		if !ok {
			e.Log.Warning(fmt.Sprintf("parameter '%s' does not appear to be injectable", point.Name))
			continue
		}
		e.Log.Success(fmt.Sprintf("parameter '%s' is injectable (%s, %s)", point.Name, technique, boundary.String()))

		session := &Session{
			Target:      e.Opts.URL,
			Method:      point.Method,
			Point:       point,
			DBMS:        heuristicDBMS,
			Technique:   technique,
			Boundary:    boundary,
			Confidence:  0.9,
			BaselineLen: baseLen,
			BaselineMS:  e.BaselineTime.Milliseconds(),
			WAF:         waf.Name,
		}
		if e.Opts.DBMS != "" {
			session.DBMS = e.Opts.DBMS
		}
		e.IdentifyDBMS(session)

		if session.Technique == "union" {
			if cols, col, ok := e.DetectUnionColumns(session); ok {
				session.Columns = cols
				session.StringCol = col
				e.Log.Info(fmt.Sprintf("UNION query: %d columns, string column %d", cols, col+1))
			}
		}

		e.Session = session
		results = append(results, Result{
			Parameter:   point.Name,
			Type:        technique,
			Payload:     boundary.Prefix + boundary.Suffix,
			DBMS:        session.DBMS,
			DBMSVersion: session.DBMSVersion,
			Details:     fmt.Sprintf("%s parameter, %s technique", point.Location, technique),
			Confidence:  session.Confidence,
			Location:    string(point.Location),
			Technique:   technique,
			Prefix:      boundary.Prefix,
			Suffix:      boundary.Suffix,
			Columns:     session.Columns,
		})

		explorer := NewExplorer(e, session)
		results = append(results, explorer.Run()...)
		// One confirmed injection is enough for the extraction phase. The
		// remaining parameters are still reported when they are confirmed,
		// but extraction is not repeated for each one.
		break
	}

	if len(results) == 0 {
		e.Log.Warning("no injectable parameter confirmed; falling back to payload library scan")
		return e.Start()
	}
	return results
}

// SessionResult converts the current session into a machine-readable result.
func (e *Engine) SessionResult() Result {
	if e.Session == nil {
		return Result{Parameter: "error", Type: "fatal", Payload: "no session", DBMS: "", Confidence: 0}
	}
	s := e.Session
	return Result{
		Parameter:  s.Point.Name,
		Type:       "session",
		Payload:    strings.Join([]string{s.Boundary.Prefix, s.Boundary.Suffix}, "|"),
		DBMS:       s.DBMS,
		Details:    fmt.Sprintf("%s %s", s.Point.Location, s.Technique),
		Confidence: s.Confidence,
		Location:   string(s.Point.Location),
		Technique:  s.Technique,
		Prefix:     s.Boundary.Prefix,
		Suffix:     s.Boundary.Suffix,
		Columns:    s.Columns,
	}
}
