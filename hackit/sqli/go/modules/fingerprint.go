package modules

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	rustLib             = syscall.NewLazyDLL("./rust_engine/target/release/rust_engine.dll")
	rustDetectDBVersion = rustLib.NewProc("rust_detect_db_version")
	freeRustString      = rustLib.NewProc("free_rust_string")
)

// Fingerprinter handles DBMS identification
type Fingerprinter struct {
	Engine EngineInterface
}

func NewFingerprinter(e EngineInterface) *Fingerprinter {
	return &Fingerprinter{Engine: e}
}

func FingerprintDBMS(body string, headers map[string][]string) string {
	// Use Rust for enhanced detection if possible
	rustResult := callRustDetect(body)
	if rustResult != "" && !strings.Contains(rustResult, "Unknown") {
		return rustResult
	}

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
	if pb, ok := headers["X-Powered-By"]; ok {
		for _, v := range pb {
			if strings.Contains(v, "PHP") {
				return "Likely MySQL (via PHP)"
			}
		}
	}

	return "Unknown"
}

func callRustDetect(banner string) string {
	cStr, _ := syscall.BytePtrFromString(banner)
	ret, _, _ := rustDetectDBVersion.Call(uintptr(unsafe.Pointer(cStr)))
	if ret == 0 {
		return ""
	}
	defer freeRustString.Call(ret)

	p := (*byte)(unsafe.Pointer(ret))
	var s []byte
	for *p != 0 {
		s = append(s, *p)
		ret++
		p = (*byte)(unsafe.Pointer(ret))
	}
	return string(s)
}
