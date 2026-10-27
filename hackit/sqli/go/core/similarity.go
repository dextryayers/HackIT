package core

import (
	"math"
	"regexp"
	"strings"
)

var whitespaceRE = regexp.MustCompile(`\s+`)
var dynamicTokenRE = regexp.MustCompile(`(?i)(csrf[_-]?token|nonce|request[_-]?id|trace[_-]?id|timestamp|authenticity_token)[^a-z0-9]{0,4}[a-z0-9_-]{8,}`)

// normalizeResponse reduces a response to a stable representation used for
// comparisons. Dynamic tokens and whitespace are removed because they cause
// false positives during boolean and time based checks.
func normalizeResponse(body string) string {
	body = strings.ToLower(body)
	body = dynamicTokenRE.ReplaceAllString(body, "$1")
	body = whitespaceRE.ReplaceAllString(body, " ")
	return strings.TrimSpace(body)
}

// similarity returns a value between 0 and 1. It combines length similarity
// with a token-set Jaccard index so that small reflected payloads do not
// dominate the result.
func similarity(a, b string) float64 {
	if a == b {
		return 1
	}
	if a == "" || b == "" {
		return 0
	}
	na := normalizeResponse(a)
	nb := normalizeResponse(b)
	if na == nb {
		return 1
	}

	la := float64(len(na))
	lb := float64(len(nb))
	lengthScore := math.Min(la, lb) / math.Max(la, lb)

	ta := tokenSet(na)
	tb := tokenSet(nb)
	if len(ta) == 0 || len(tb) == 0 {
		return lengthScore
	}
	inter := 0
	for token := range ta {
		if tb[token] {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	jaccard := float64(inter) / float64(union)
	return 0.45*lengthScore + 0.55*jaccard
}

func tokenSet(s string) map[string]bool {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == '<' || r == '>' || r == '"' || r == '\''
	})
	out := make(map[string]bool, len(fields))
	for _, f := range fields {
		if len(f) >= 3 {
			out[f] = true
		}
	}
	return out
}

// similarityThreshold is the point below which two responses are considered
// different. It is intentionally conservative to avoid false positives.
const similarityThreshold = 0.82

func responsesDiffer(a, b string) bool {
	return similarity(a, b) < similarityThreshold
}

func responsesSimilar(a, b string) bool {
	return similarity(a, b) >= similarityThreshold
}

func isErrorLike(body string, dbms string) bool {
	lower := strings.ToLower(body)
	generic := []string{
		"sql syntax", "syntax error", "unclosed quotation", "quoted string not properly terminated",
		"mysql_fetch", "mysqli", "pg_query", "postgresql", "ora-", "oracle error",
		"microsoft ole db", "sql server", "sqlite", "sqlite3", "db::exception",
		"catalog error", "binder error", "dynamic sql error", "general error",
		"warning: mysql", "division by zero", "invalid input syntax",
	}
	for _, p := range generic {
		if strings.Contains(lower, p) {
			return true
		}
	}
	if dbms != "" {
		for _, p := range dbmsErrorPatterns(dbms) {
			if strings.Contains(lower, strings.ToLower(p)) {
				return true
			}
		}
	}
	return false
}

func dbmsErrorPatterns(dbms string) []string {
	switch strings.ToLower(dbms) {
	case "mysql":
		return []string{"you have an error in your sql syntax", "mysql_fetch", "mysql_error", "mariadb"}
	case "mariadb":
		return []string{"you have an error in your sql syntax", "mariadb", "mysql_fetch"}
	case "postgresql":
		return []string{"postgresql", "pg_query", "syntax error at or near", "invalid input syntax"}
	case "mssql":
		return []string{"microsoft ole db", "unclosed quotation mark", "sql server", "conversion failed"}
	case "oracle":
		return []string{"ora-", "oracle", "pls-", "oci_"}
	case "sqlite":
		return []string{"sqlite", "no such table", "no such column"}
	case "clickhouse":
		return []string{"clickhouse", "db::exception"}
	case "duckdb":
		return []string{"duckdb", "catalog error", "binder error"}
	case "cockroachdb":
		return []string{"cockroachdb", "crdb_", "runtime error"}
	case "snowflake":
		return []string{"snowflake", "execution error in"}
	case "bigquery":
		return []string{"bigquery", "unrecognized token"}
	case "firebird":
		return []string{"firebird", "dynamic sql error", "isc_"}
	case "sybase":
		return []string{"sybase", "sql anywhere"}
	case "h2":
		return []string{"org.h2", "general error", "unique index or primary key violation"}
	}
	return nil
}

// bestMatch returns the DBMS whose error signature matches the body. It is
// used when the initial heuristic fingerprint is inconclusive.
func bestErrorMatch(body string) string {
	candidates := []string{
		"MySQL", "MariaDB", "PostgreSQL", "MSSQL", "Oracle", "SQLite",
		"ClickHouse", "DuckDB", "CockroachDB", "Snowflake", "BigQuery",
		"Firebird", "Sybase", "H2",
	}
	for _, dbms := range candidates {
		if isErrorLike(body, dbms) {
			return dbms
		}
	}
	return ""
}
