package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func detectIface() string {
	cmd := exec.Command("iw", "dev")
	out, err := cmd.Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Interface") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					return parts[len(parts)-1]
				}
			}
		}
	}
	return ""
}

type WebServer struct {
	Server   *http.Server
	Port     int
	Running  bool
	mu       sync.Mutex
	scanner  *AggressiveScanner
	attack   *RealAttack
	cracker  *CrackEngine
}

type ScanRequest struct {
	Interface string `json:"interface"`
	Band      string `json:"band"`
}

type AttackRequest struct {
	Type    string `json:"type"`
	Iface   string `json:"iface"`
	BSSID   string `json:"bssid"`
	Station string `json:"station"`
	SSIDs   string `json:"ssids"`
	Count   int    `json:"count"`
	Rate    int    `json:"rate"`
	Timeout int    `json:"timeout"`
}

type APIResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func NewWebServer(port int) *WebServer {
	return &WebServer{
		Port:    port,
		scanner: NewAggressiveScanner(detectIface()),
		attack:  NewRealAttack(),
		cracker: NewCrackEngine(),
	}
}

func (w *WebServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		rw.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		rw.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		rw.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			rw.WriteHeader(http.StatusOK)
			return
		}

		next(rw, r)
	}
}

func (w *WebServer) Start(port int) {
	w.mu.Lock()
	w.Port = port
	w.Running = true
	w.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", w.corsMiddleware(w.handleHealth))
	mux.HandleFunc("/status", w.corsMiddleware(w.handleStatus))
	mux.HandleFunc("/scan", w.corsMiddleware(w.handleScan))
	mux.HandleFunc("/attack", w.corsMiddleware(w.handleAttack))
	mux.HandleFunc("/deauth", w.corsMiddleware(w.handleDeauth))

	w.Server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		w.Stop()
	}()

	fmt.Printf("[GO-WEB] HackIT REST server starting on port %d\n", port)
	if err := w.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[GO-WEB] Server error: %v\n", err)
	}
}

func (w *WebServer) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.Running && w.Server != nil {
		fmt.Println("[GO-WEB] Shutting down HackIT REST server...")
		w.Server.Close()
		w.Running = false
		fmt.Println("[GO-WEB] Server stopped")
	}
}

func (w *WebServer) writeJSON(rw http.ResponseWriter, status int, resp APIResponse) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	json.NewEncoder(rw).Encode(resp)
}

func (w *WebServer) handleHealth(rw http.ResponseWriter, r *http.Request) {
	w.writeJSON(rw, http.StatusOK, APIResponse{
		Status:  "ok",
		Message: "HackIT wireless worker is running",
		Data: map[string]interface{}{
			"version": "2.0.0",
			"uptime":  time.Now().Unix(),
		},
	})
}

func (w *WebServer) handleStatus(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	running := w.Running
	w.mu.Unlock()

	w.writeJSON(rw, http.StatusOK, APIResponse{
		Status: "ok",
		Data: map[string]interface{}{
			"server_running": running,
			"port":           w.Port,
			"timestamp":      time.Now().Unix(),
		},
	})
}

func (w *WebServer) handleScan(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.writeJSON(rw, http.StatusMethodNotAllowed, APIResponse{Status: "error", Message: "POST required"})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.writeJSON(rw, http.StatusBadRequest, APIResponse{Status: "error", Message: "invalid body"})
		return
	}
	defer r.Body.Close()

	var req ScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.writeJSON(rw, http.StatusBadRequest, APIResponse{Status: "error", Message: "invalid JSON"})
		return
	}

	if req.Interface != "" {
		w.scanner.Interface = req.Interface
	}

	go func() {
		results := w.scanner.ScanAllBands()
		w.scanner.Results = results
	}()

	w.writeJSON(rw, http.StatusAccepted, APIResponse{
		Status:  "scan_started",
		Message: "Scan initiated on " + w.scanner.Interface,
	})
}

func (w *WebServer) handleAttack(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.writeJSON(rw, http.StatusMethodNotAllowed, APIResponse{Status: "error", Message: "POST required"})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.writeJSON(rw, http.StatusBadRequest, APIResponse{Status: "error", Message: "invalid body"})
		return
	}
	defer r.Body.Close()

	var req AttackRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.writeJSON(rw, http.StatusBadRequest, APIResponse{Status: "error", Message: "invalid JSON"})
		return
	}

	params := AttackParams{
		Iface:   req.Iface,
		BSSID:   req.BSSID,
		Station: req.Station,
		SSIDs:   req.SSIDs,
		Count:   req.Count,
		Rate:    req.Rate,
		Timeout: req.Timeout,
		Type:    req.Type,
	}

	go func() {
		if err := w.attack.ExecuteAttack(req.Type, params); err != nil {
			fmt.Printf("[GO-WEB] Attack error: %v\n", err)
		}
	}()

	w.writeJSON(rw, http.StatusAccepted, APIResponse{
		Status:  "attack_started",
		Message: fmt.Sprintf("%s attack initiated", req.Type),
	})
}

func (w *WebServer) handleDeauth(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.writeJSON(rw, http.StatusMethodNotAllowed, APIResponse{Status: "error", Message: "POST required"})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.writeJSON(rw, http.StatusBadRequest, APIResponse{Status: "error", Message: "invalid body"})
		return
	}
	defer r.Body.Close()

	var req AttackRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.writeJSON(rw, http.StatusBadRequest, APIResponse{Status: "error", Message: "invalid JSON"})
		return
	}

	if req.Count <= 0 {
		req.Count = 64
	}

	go func() {
		if err := w.attack.Deauth(req.Iface, req.BSSID, req.Station, req.Count); err != nil {
			fmt.Printf("[GO-WEB] Deauth error: %v\n", err)
		}
	}()

	w.writeJSON(rw, http.StatusAccepted, APIResponse{
		Status:  "deauth_started",
		Message: fmt.Sprintf("Deauth %s -> %s (%d packets)", req.BSSID, req.Station, req.Count),
	})
}

var _ = os.Stdout
