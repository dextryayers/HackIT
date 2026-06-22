package types

// Result represents a single finding from the engine
type Result struct {
	Parameter  string  `json:"parameter"`
	Type       string  `json:"type"`
	Payload    string  `json:"payload"`
	DBMS       string  `json:"dbms"`
	Details    string  `json:"details"`
	Confidence float64 `json:"confidence"`
}

// EngineInterface defines methods needed from the core engine
type EngineInterface interface {
	GetLogger() LoggerInterface
	Request(payload, param string) (string, int, interface{}, error)
}

// LoggerInterface defines logging methods
type LoggerInterface interface {
	Info(msg string)
	Warning(msg string)
	Success(msg string)
	Debug(msg string)
	Payload(param, payload string)
}
