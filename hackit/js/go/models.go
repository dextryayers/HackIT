package main

type DiscoveryType string

const (
	TypeTag      DiscoveryType = "Script Tag"
	TypeHidden   DiscoveryType = "Heuristic/Hidden"
	TypeEndpoint DiscoveryType = "Web Endpoint"
	TypeNested   DiscoveryType = "Nested JS"
	TypeMap      DiscoveryType = "Source Map"
	TypeRobots   DiscoveryType = "Robots.txt"
	TypeActive   DiscoveryType = "Active Brute"
	TypeSensitive DiscoveryType = "Sensitive Data"
	TypeComment  DiscoveryType = "Code Comment"
)

type Result struct {
	SourceURL string        `json:"source_url"`
	URL       string        `json:"url"`
	Type      DiscoveryType `json:"type"`
	Ext       string        `json:"extension"`
}

type ScanOutput struct {
	Target  string   `json:"target"`
	Results []Result `json:"results"`
	Total   int      `json:"total"`
	JSCount int      `json:"js_count"`
}
