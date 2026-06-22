package modules

import (
	"hackit/sqli/go/utils"
	"net/http"
)

// EngineInterface defines the methods needed from the core engine
type EngineInterface interface {
	GetLogger() *utils.Logger
	Request(payload, param string) (string, int, http.Header, error)
}

// Result represents a single finding (mirrors core.Result to avoid import cycles)
type Result struct {
	Parameter  string  `json:"parameter"`
	Type       string  `json:"type"`
	Payload    string  `json:"payload"`
	DBMS       string  `json:"dbms"`
	Details    string  `json:"details"`
	Confidence float64 `json:"confidence"`
}
