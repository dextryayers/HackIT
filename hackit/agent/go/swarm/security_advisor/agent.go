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
func (s *SecurityAdvisorAgent) Description() string  { return s.desc }

func (s *SecurityAdvisorAgent) Execute(state *core.SwarmState) error {
	state.Section("SECURITY ADVISOR PHASE")
	state.Log(s.Name(), "START", "Starting Security Advisory and Mitigation Matrix...")

	state.Mu.Lock()
	vulns := state.Vulns
	state.Mu.Unlock()

	if len(vulns) == 0 {
		state.LogWarn(s.Name(), "WARN", "No vulnerabilities to advise on.")
		return nil
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sGenerating %d mitigation strategies%s", core.Yellow, len(vulns), core.Reset))

	type recommendation struct {
		id     string
		mitigation string
	}

	recs := []recommendation{
		{"MISCONF-001", "Restrict .env access: nginx 'location ~ /\\.env { deny all; }' or apache 'Files \".env\" { Require all denied }'. Immediately rotate all exposed credentials."},
		{"MISCONF-002", "Remove .git from production. Add 'RedirectMatch 404 /\\.git' to web server config. Regenerate any secrets exposed in git history."},
		{"MISCONF-WP-ADMIN", "Rename wp-admin, enforce IP whitelisting, implement 2FA, install WAF rules for login protection."},
		{"MISCONF-PHPINFO", "Delete phpinfo.php immediately. Add 'location ~ \\.php$ { deny all; }' for unused PHP files."},
		{"MISCONF-ACTUATOR", "Set 'management.endpoints.web.exposure.include=health' only. Add Spring Security. Block /actuator at reverse proxy."},
		{"MISCONF-SWAGGER", "Disable Swagger UI in production. Set 'springdoc.api-docs.enabled=false' and 'springdoc.swagger-ui.enabled=false'."},
		{"MISCONF-MYSQL", "Never expose MySQL to internet. Bind to 127.0.0.1. Use SSH tunnel or VPN for remote access."},
		{"MISCONF-MONGO", "Enable MongoDB authentication, bind to localhost, enable TLS, audit unauthorized access."},
		{"MISCONF-FTP", "Disable FTP. Use SFTP or SCP instead. If FTP required, enforce TLS and strong passwords."},
		{"CVE-2023-XXXX", "Update WordPress core, themes, and plugins to latest versions. Disable XML-RPC if unused."},
		{"CVE-2020-15778", "Upgrade OpenSSH to >= 8.3p1. Disable SCP in sshd_config: 'Subsystem sftp /usr/lib/ssh/sftp-server'."},
		{"CVE-2021-41773", "Upgrade Apache to >= 2.4.50. Add 'Require all denied' for CGI directories."},
		{"CVE-2021-23017", "Upgrade Nginx to >= 1.21.0. Disable resolver in server blocks unless absolutely needed."},
		{"CVE-2021-31166", "Apply Microsoft security patch KB5003637. Disable HTTP/2 on IIS if not required."},
		{"CVE-2022-0543", "Upgrade Redis to >= 6.2.7. Set 'rename-command FLUSHALL \"\"' and enable 'requirepass'."},
		{"TECH-VULN", "Apply all vendor security patches. Enable automatic security updates where possible."},
	}

	recMap := map[string]string{}
	for _, r := range recs {
		recMap[r.id] = r.mitigation
	}

	count := 0
	state.Mu.Lock()
	for i := range state.Vulns {
		if m, ok := recMap[state.Vulns[i].ID]; ok {
			state.Vulns[i].Description += "\n\nMITIGATION: " + m
			count++
		} else {
			state.Vulns[i].Description += "\n\nMITIGATION: Apply vendor patches and restrict network access to the affected service."
			count++
		}
	}
	state.Mu.Unlock()

	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(s.Name(), "RESULT", fmt.Sprintf("Generated mitigations for %d vulns in %s", count, elapsed))
	return nil
}
