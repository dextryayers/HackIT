package main

import (
	"fmt"
	"strings"
)

func runPermutations(foundSubs []*Result, domain string, jobs chan<- string) {
	fmt.Println("[*] Running Permutation Scanning...")

	// Advanced permutation list (Expert Altdns & Subjack style) - Deeply improved for massive coverage
	permWords := []string{
		"dev", "stg", "test", "admin", "prod", "beta", "vpn", "mail", "web",
		"internal", "corp", "demo", "stage", "staging", "api", "app", "cdn",
		"static", "assets", "img", "images", "media", "files", "download",
		"upload", "auth", "login", "sso", "gateway", "edge", "ws", "shop",
		"payment", "payments", "checkout", "order", "account", "customer",
		"jenkins", "gitlab", "jira", "wiki", "docs", "portal", "support",
		"monitor", "status", "grafana", "prometheus", "elastic", "kibana",
		"v1", "v2", "v3", "api-v1", "api-v2", "backend", "frontend", "client",
		"partner", "m", "mobile", "app-api", "uat", "preprod", "sandbox",
		"secret", "private", "devops", "kubernetes", "k8s", "docker", "registry",
		"db", "database", "sql", "redis", "mongo", "infra", "secure", "security",
		"backup", "storage", "s3", "bucket", "blob", "aws", "azure", "gcp",
		"lb", "proxy", "waf", "cloud", "vault", "office", "work", "remote",
		"sys", "system", "tools", "util", "utils", "config", "config", "ops",
		"ci", "cd", "build", "deploy", "release", "admin-panel", "dashboard",
		"intranet", "extranet", "vpn-gw", "ssh", "ftp", "sftp", "smtp", "imap",
		"pop3", "mx", "ns", "dns", "dns1", "dns2", "git", "svn", "repo",
		"search", "find", "query", "analytics", "stats", "metrics", "data",
		"pay", "billing", "invoice", "crm", "erp", "hr", "sales", "marketing",
	}

	// Dynamic word generation (common patterns)
	patterns := []string{"01", "02", "1", "2", "old", "new", "test1", "test2"}

	count := 0
	for _, res := range foundSubs {
		sub := res.Subdomain
		// Strip domain
		prefix := strings.TrimSuffix(sub, "."+domain)
		if prefix == sub {
			continue // Should not happen
		}

		for _, w := range permWords {
			// 1. Dash
			jobs <- fmt.Sprintf("%s-%s.%s", prefix, w, domain)
			jobs <- fmt.Sprintf("%s-%s.%s", w, prefix, domain)

			// 2. Dot (already covered by recursion/brute mostly, but good to ensure)
			jobs <- fmt.Sprintf("%s.%s.%s", prefix, w, domain)
			jobs <- fmt.Sprintf("%s.%s.%s", w, prefix, domain)

			// 3. No separator
			jobs <- fmt.Sprintf("%s%s.%s", prefix, w, domain)
			jobs <- fmt.Sprintf("%s%s.%s", w, prefix, domain)

			count += 6
		}

		// 4. Pattern-based permutations
		for _, p := range patterns {
			jobs <- fmt.Sprintf("%s%s.%s", prefix, p, domain)
			jobs <- fmt.Sprintf("%s-%s.%s", prefix, p, domain)
			count += 2
		}
	}
	fmt.Printf("[*] Generated %d permutations\n", count)
}
