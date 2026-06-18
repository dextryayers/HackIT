package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type ParamType string

const (
	TypeString     ParamType = "string"
	TypeNumeric    ParamType = "numeric"
	TypeBase64     ParamType = "base64"
	TypeJWT        ParamType = "jwt"
	TypeHash       ParamType = "hash"
	TypeUUID       ParamType = "uuid"
	TypeEmail      ParamType = "email"
	TypeURL        ParamType = "url"
	TypePath       ParamType = "path"
	TypeBoolean    ParamType = "boolean"
	TypeArray      ParamType = "array"
	TypeObject     ParamType = "object"
	TypeDate       ParamType = "date"
	TypeTimestamp  ParamType = "timestamp"
	TypeGraphQL    ParamType = "graphql"
	TypeEmpty      ParamType = "empty"
	TypeUnknown    ParamType = "unknown"
	TypeSensitive  ParamType = "sensitive"
)

type Severity string

const (
	SeverityInfo     Severity = "Info"
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

type PathParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type DecodeResult struct {
	Original string `json:"original"`
	Decoded  string `json:"decoded"`
	Layers   int    `json:"layers"`
	Types    string `json:"types"`
	IOC      bool   `json:"ioc"`
}

type ValueMine struct {
	Param     string   `json:"param"`
	Pattern   string   `json:"pattern"`
	Examples  []string `json:"examples"`
	Confidence string   `json:"confidence"`
}

type DiscoResult struct {
	URL         string            `json:"url"`
	Domain      string            `json:"domain"`
	Source      string            `json:"source"`
	Params      map[string]string `json:"params"`
	ParamNames  []string          `json:"param_names"`
	ParamCount  int               `json:"param_count"`
	Path        string            `json:"path"`
	FileExt     string            `json:"file_ext,omitempty"`
	PathParams  []PathParam       `json:"path_params,omitempty"`
}

type ParamDetail struct {
	Name       string    `json:"name"`
	Type       ParamType `json:"param_type"`
	Sample     string    `json:"sample,omitempty"`
	HasValue   bool      `json:"has_value"`
	IsEmpty    bool      `json:"is_empty"`
	Sensitive  bool      `json:"sensitive"`
	URLCount   int       `json:"url_count"`
	Sources    []string  `json:"sources"`
}

type Finding struct {
	Type        string   `json:"finding_type"`
	Category    string   `json:"category"`
	Param       string   `json:"param,omitempty"`
	URL         string   `json:"url,omitempty"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
}

type FuzzResult struct {
	Param     string `json:"param"`
	Payload   string `json:"payload"`
	URL       string `json:"url"`
	Reflected bool   `json:"reflected"`
	Context   string `json:"context,omitempty"`
	Error     string `json:"error,omitempty"`
	Status    int    `json:"status"`
	Method    string `json:"method"`
	RTT_MS    int64  `json:"rtt_ms"`
}

type ScanSummary struct {
	Domain         string `json:"domain"`
	URLsDiscovered int    `json:"urls_discovered"`
	UniqueParams   int    `json:"unique_params"`
	FuzzResults    int    `json:"fuzz_results"`
	Findings       int    `json:"findings"`
	SourcesHit     int    `json:"sources_hit"`
	DurationMS     int64  `json:"duration_ms"`
}

func emitJSON(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Println(string(data))
}

func emitTyped(typ string, v interface{}) {
	m := map[string]interface{}{"type": typ}
	if obj, ok := v.(map[string]interface{}); ok {
		for k, v := range obj {
			m[k] = v
		}
	} else {
		data, _ := json.Marshal(v)
		var obj map[string]interface{}
		json.Unmarshal(data, &obj)
		for k, v := range obj {
			m[k] = v
		}
	}
	emitJSON(m)
}

func debugLog(format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[DBG] " + format + "\n", args...)
	}
}
