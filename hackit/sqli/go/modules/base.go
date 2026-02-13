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
