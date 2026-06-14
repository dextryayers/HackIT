package modules

import (
	"net/http"
	"strings"
)

// Fingerprinter handles DBMS identification
type Fingerprinter struct {
	Engine EngineInterface
}

func NewFingerprinter(e EngineInterface) *Fingerprinter {
	return &Fingerprinter{Engine: e}
}

func FingerprintDBMS(body string, headers http.Header) string {
	// Fallback to Go logic
	// MySQL
	if strings.Contains(body, "SQL syntax") || strings.Contains(body, "mysql_fetch") {
		return "MySQL"
	}

	// PostgreSQL
	if strings.Contains(body, "PostgreSQL") || strings.Contains(body, "pg_query") {
		return "PostgreSQL"
	}

	// MSSQL
	if strings.Contains(body, "Microsoft OLE DB Provider for SQL Server") || strings.Contains(body, "SQLServer JDBC Driver") {
		return "MSSQL"
	}

	// Oracle
	if strings.Contains(body, "ORA-00933") || strings.Contains(body, "Oracle Error") {
		return "Oracle"
	}

	// SQLite
	if strings.Contains(body, "sqlite3.OperationalError") || strings.Contains(body, "SQLite/JDBCDriver") {
		return "SQLite"
	}

	// X-Powered-By check
	if pb := headers.Get("X-Powered-By"); pb != "" {
		if strings.Contains(pb, "PHP") {
			return "Likely MySQL (via PHP)"
		}
	}

	return "Unknown"
}
