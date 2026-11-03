package security_advisor

import (
	"fmt"
	"time"

	"hackit_ai_engine/swarm/core"
)

type SecurityAdvisorAgent struct {
	name string
	desc string
}

func NewSecurityAdvisorAgent() *SecurityAdvisorAgent {
	return &SecurityAdvisorAgent{
		name: "Agent-15: Security Advisor",
		desc: "Provides technical explanations, risk levels, and mitigation best practices based on findings.",
	}
}

func (s *SecurityAdvisorAgent) Name() string        { return s.name }
func (s *SecurityAdvisorAgent) Description() string { return s.desc }

var mitigations = map[string]string{
	"MISCONF-001":           "Restrict .env access: nginx 'location ~ /\\.env { deny all; }' or apache 'Files \".env\" { Require all denied }'. Immediately rotate all exposed credentials.",
	"MISCONF-002":           "Remove .git from production. Add 'RedirectMatch 404 /\\.git' to web server config. Regenerate any secrets exposed in git history.",
	"MISCONF-PHPINFO":       "Delete phpinfo.php immediately. Add 'location ~ \\.php$ { deny all; }' for unused PHP files.",
	"MISCONF-ACTUATOR":      "Set 'management.endpoints.web.exposure.include=health' only. Add Spring Security. Block /actuator at reverse proxy.",
	"MISCONF-SWAGGER":       "Disable Swagger UI in production. Set 'springdoc.api-docs.enabled=false' and 'springdoc.swagger-ui.enabled=false'.",
	"MISCONF-GRAPHQL":       "Disable introspection in production and require authentication for the GraphQL endpoint.",
	"MISCONF-SERVER-STATUS": "Disable mod_status, or restrict it to localhost: 'SetHandler server-status' inside a 'Require local' block.",
	"MISCONF-FTP-ANON":      "Disable anonymous FTP. Use SFTP or SCP instead. If FTP is required, enforce TLS and strong passwords.",
	"CVE-2021-41773":        "Upgrade Apache to >= 2.4.50. Add 'Require all denied' for CGI directories.",
	"EOL-APACHE22":          "Upgrade Apache to a supported release (2.4.x current).",
	"EOL-NGINX":             "Upgrade nginx to a supported stable release.",
	"EOL-OPENSSH":           "Upgrade OpenSSH to a supported release and disable weak algorithms.",
	"EOL-IIS":               "Upgrade IIS / Windows Server to a supported version and apply all security patches.",
	"EOL-PHP":               "Upgrade PHP to a supported release; unsupported versions receive no security fixes.",
}

func (s *SecurityAdvisorAgent) Execute(state *core.SwarmState) error {
	state.Section("SECURITY ADVISOR PHASE")
	state.Log(s.Name(), "START", "Starting Security Advisory and Mitigation Matrix...")

	state.Mu.RLock()
	vulnCount := len(state.Vulns)
	state.Mu.RUnlock()

	if vulnCount == 0 {
		state.LogWarn(s.Name(), "WARN", "No vulnerabilities to advise on.")
		return nil
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sGenerating %d mitigation strategies%s", core.Yellow, vulnCount, core.Reset))

	count := 0
	state.Mu.Lock()
	for i := range state.Vulns {
		if state.Vulns[i].Remediation != "" {
			continue
		}
		if m, ok := mitigations[state.Vulns[i].ID]; ok {
			state.Vulns[i].Remediation = m
		} else {
			state.Vulns[i].Remediation = "Apply vendor patches and restrict network access to the affected service."
		}
		count++
	}
	state.Mu.Unlock()

	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(s.Name(), "RESULT", fmt.Sprintf("Generated mitigations for %d vulns in %s", count, elapsed))
	return nil
}
