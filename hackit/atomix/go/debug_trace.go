package main

import (
	"fmt"
	"os"
	"time"
)

type TraceEntry struct {
	Timestamp  time.Time
	TemplateID string
	Event      string
	Detail     string
	Duration   time.Duration
}

type TraceSession struct {
	ID        string
	StartTime time.Time
	Entries   []TraceEntry
	MaxLength int
	file      *os.File
}

type Debugger struct {
	sessions map[string]*TraceSession
	enabled  bool
	verbose  bool
}

func NewDebugger(verbose bool) *Debugger {
	return &Debugger{
		sessions: make(map[string]*TraceSession),
		enabled:  verbose,
		verbose:  verbose,
	}
}

func (d *Debugger) StartSession(id string, filePath string) *TraceSession {
	session := &TraceSession{
		ID:        id,
		StartTime: time.Now(),
		MaxLength: 1000,
	}
	if filePath != "" {
		f, err := os.Create(filePath)
		if err == nil {
			session.file = f
			fmt.Fprintf(f, "Trace Session: %s\n", id)
			fmt.Fprintf(f, "Started: %s\n", time.Now().UTC().Format(time.RFC3339))
			fmt.Fprintf(f, "---\n")
		}
	}
	d.sessions[id] = session
	return session
}

func (d *Debugger) Log(sessionID, templateID, event, detail string) {
	session, ok := d.sessions[sessionID]
	if !ok { return }

	entry := TraceEntry{
		Timestamp:  time.Now(),
		TemplateID: templateID,
		Event:      event,
		Detail:     detail,
	}
	session.Entries = append(session.Entries, entry)

	if len(session.Entries) > session.MaxLength {
		session.Entries = session.Entries[len(session.Entries)-session.MaxLength:]
	}

	if session.file != nil {
		fmt.Fprintf(session.file, "[%s] %s: %s | %s\n",
			entry.Timestamp.Format("15:04:05.000"), templateID, event, detail)
	}

	if d.verbose {
		fmt.Fprintf(os.Stderr, "  %s [%s] %s: %s\n",
			SColor(ColorDim, "TRACE"),
			SColor(ColorCyan, templateID),
			SColor(ColorYellow, event),
			SColor(ColorBWhite, detail),
		)
	}
}

func (d *Debugger) CloseSession(id string) {
	session, ok := d.sessions[id]
	if !ok { return }
	if session.file != nil {
		fmt.Fprintf(session.file, "---\n")
		fmt.Fprintf(session.file, "Duration: %s\n", time.Since(session.StartTime).Round(time.Millisecond))
		fmt.Fprintf(session.file, "Entries: %d\n", len(session.Entries))
		session.file.Close()
	}
	delete(d.sessions, id)
}

func (d *Debugger) PrintSession(id string) {
	session, ok := d.sessions[id]
	if !ok {
		fmt.Fprintf(os.Stderr, "%s Session not found: %s\n",
			SColor(ColorRed, "[!]"), id)
		return
	}
	fmt.Printf("\n=== TRACE: %s (%d entries) ===\n", id, len(session.Entries))
	for _, e := range session.Entries {
		fmt.Printf("[%s] %-25s %-15s %s\n",
			e.Timestamp.Format("15:04:05.000"),
			e.TemplateID,
			e.Event,
			e.Detail,
		)
	}
}

type TemplateDebugInfo struct {
	TemplateID string
	RequestURL string
	StatusCode int
	BodyLen    int
	BodySnippet string
	MatchDebug  string
	Vars        map[string]string
	Duration    time.Duration
}

func (d *Debugger) DebugMatch(tdi *TemplateDebugInfo) {
	if !d.verbose { return }
	fmt.Fprintf(os.Stderr, "\n  %s %s\n",
		SColor(ColorBCyan, "═══"),
		SColor(ColorBWhite, "MATCH DEBUG"))
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		SColor(ColorBWhite, "Template:"),
		SColor(ColorCyan, tdi.TemplateID))
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		SColor(ColorBWhite, "URL:"),
		SColor(ColorDim, tdi.RequestURL))
	fmt.Fprintf(os.Stderr, "  %s %d (%s)\n",
		SColor(ColorBWhite, "Status:"),
		tdi.StatusCode, ColorStatus(tdi.StatusCode))
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		SColor(ColorBWhite, "Body:"),
		SColor(ColorDim, fmt.Sprintf("%d bytes", tdi.BodyLen)))
	if tdi.BodySnippet != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			SColor(ColorBWhite, "Snippet:"),
			SColor(ColorYellow, truncateString(tdi.BodySnippet, 200)))
	}
	if tdi.MatchDebug != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			SColor(ColorBWhite, "Match:"),
			SColor(ColorGreen, tdi.MatchDebug))
	}
	if len(tdi.Vars) > 0 {
		for k, v := range tdi.Vars {
			fmt.Fprintf(os.Stderr, "  %s %s = %s\n",
				SColor(ColorBWhite, "Var:"),
				SColor(ColorCyan, k),
				SColor(ColorDim, v))
		}
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen { return s }
	return s[:maxLen] + "..."
}

func (d *Debugger) IsEnabled() bool { return d.enabled }

type TraceLogger struct {
	*Debugger
	sessionID string
}

func NewTraceLogger(sessionID string, verbose bool) *TraceLogger {
	d := NewDebugger(verbose)
	d.StartSession(sessionID, "")
	return &TraceLogger{Debugger: d, sessionID: sessionID}
}

func (tl *TraceLogger) Logf(templateID, event, format string, args ...interface{}) {
	detail := fmt.Sprintf(format, args...)
	tl.Log(tl.sessionID, templateID, event, detail)
}

func (tl *TraceLogger) LogRequest(templateID, method, url string) {
	tl.Logf(templateID, "REQUEST", "%s %s", method, url)
}

func (tl *TraceLogger) LogResponse(templateID string, statusCode int, bodyLen int) {
	tl.Logf(templateID, "RESPONSE", "%d (%d bytes)", statusCode, bodyLen)
}

func (tl *TraceLogger) LogMatch(templateID, matcher, extracted string) {
	tl.Logf(templateID, "MATCH", "%s -> %s", matcher, truncateString(extracted, 100))
}

func (tl *TraceLogger) LogError(templateID, err string) {
	tl.Logf(templateID, "ERROR", "%s", err)
}

func (tl *TraceLogger) Close() {
	tl.CloseSession(tl.sessionID)
}
