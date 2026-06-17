package memory

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"hackit_ai_engine/swarm/core"
)

type MemoryAgent struct {
	name string
	desc string
}

func NewMemoryAgent() *MemoryAgent {
	return &MemoryAgent{
		name: "Agent-11: Memory",
		desc: "Stores assessment results in SQLite and compares with previous scans to detect asset drift.",
	}
}

func (m *MemoryAgent) Name() string        { return m.name }
func (m *MemoryAgent) Description() string  { return m.desc }

func (m *MemoryAgent) Execute(state *core.SwarmState) error {
	state.Section("MEMORY PHASE")
	state.Log(m.Name(), "START", "Activating Long-Term Memory (LTM)...")

	dbDir := filepath.Join("data", "memory")
	os.MkdirAll(dbDir, 0755)
	dbPath := filepath.Join(dbDir, "hackit_memory.db")

	state.Mu.RLock()
	domain := state.Target.PrimaryDomain
	subdomains := state.ReconData.Subdomains
	services := state.Discovered
	vulns := state.Vulns
	state.Mu.RUnlock()

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sOpening SQLite memory at %s%s", core.Yellow, dbPath, core.Reset))

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		state.StopSpinner()
		state.LogWarn(m.Name(), "WARN", fmt.Sprintf("SQLite unavailable: %v. Running in mock mode.", err))
		time.Sleep(100 * time.Millisecond)
		state.StopSpinner()
		state.Log(m.Name(), "MOCK", fmt.Sprintf("Domain '%s' has %d subdomains, %d services, %d vulns", domain, len(subdomains), len(services), len(vulns)))
		state.LogOk(m.Name(), "COMPLETE", fmt.Sprintf("Memory mock: %d subdomains, %d services", len(subdomains), len(services)))
		return nil
	}
	defer db.Close()

	initSQL := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT,
		domain TEXT,
		timestamp TEXT,
		subdomain_count INTEGER,
		service_count INTEGER,
		vuln_count INTEGER
	);
	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT,
		subdomain TEXT,
		discovered_at TEXT
	);
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT,
		vuln_id TEXT,
		name TEXT,
		severity TEXT,
		cvss REAL,
		description TEXT
	);`
	_, err = db.Exec(initSQL)
	if err != nil {
		state.StopSpinner()
		return fmt.Errorf("SQLite init: %w", err)
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	db.Exec("INSERT INTO scans (session_id, domain, timestamp, subdomain_count, service_count, vuln_count) VALUES (?, ?, ?, ?, ?, ?)",
		state.SessionID, domain, ts, len(subdomains), len(services), len(vulns))

	for _, sub := range subdomains {
		db.Exec("INSERT INTO subdomains (session_id, subdomain, discovered_at) VALUES (?, ?, ?)",
			state.SessionID, sub, ts)
	}
	for _, v := range vulns {
		db.Exec("INSERT INTO vulnerabilities (session_id, vuln_id, name, severity, cvss, description) VALUES (?, ?, ?, ?, ?, ?)",
			state.SessionID, v.ID, v.Name, v.Severity, v.CVSS, v.Description)
	}

	var prevCount int
	err = db.QueryRow("SELECT COUNT(*) FROM subdomains WHERE domain = ? AND session_id != ?", domain, state.SessionID).Scan(&prevCount)
	if err == nil && prevCount > 0 && prevCount != len(subdomains) {
		state.LogWarn(m.Name(), "DRIFT", fmt.Sprintf("Asset drift detected: %d subdomains previously vs %d now", prevCount, len(subdomains)))
	} else {
		state.LogOk(m.Name(), "DRIFT", "No asset drift detected")
	}

	state.StopSpinner()
	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(m.Name(), "RESULT", fmt.Sprintf("Committed %d records to SQLite in %s", 1+len(subdomains)+len(vulns), elapsed))
	return nil
}

func initDbMock() *sql.DB { return nil }
