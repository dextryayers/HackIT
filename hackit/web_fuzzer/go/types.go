package main

type Result struct {
	Status   int    `json:"status"`
	Length   int64  `json:"length"`
	URL      string `json:"url"`
	Title    string `json:"title,omitempty"`
	Redirect string `json:"redirect,omitempty"`
	IsBypass bool   `json:"is_bypass,omitempty"`
	Payload  string `json:"payload,omitempty"`
	WAF      string `json:"waf,omitempty"`
}

type ShapedTarget struct {
	URL      string `json:"url"`
	WAF      string `json:"waf"`
	Priority int    `json:"priority"`
}
