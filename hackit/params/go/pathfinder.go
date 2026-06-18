package main

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	reNumericPath  = regexp.MustCompile(`^[0-9]+$`)
	reUUIDPath     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHexPath      = regexp.MustCompile(`^[0-9a-f]{32,40}$|^[0-9a-f]{64}$`)
	reSlugPath     = regexp.MustCompile(`^[a-z0-9]+(?:[-_][a-z0-9]+)*$`)
	reYearPath     = regexp.MustCompile(`^(19|20)\d{2}$`)
	reLocalePath   = regexp.MustCompile(`^[a-z]{2}([_-][A-Z]{2})?$`)
	reBase64Path   = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{10,}$`)

	knownAPIPatterns = []struct {
		prefix   string
		param    string
		extract  func(string) string
	}{
		{"user", "user_id", firstSegment},
		{"users", "user_id", firstSegment},
		{"profile", "profile_id", firstSegment},
		{"profiles", "profile_id", firstSegment},
		{"account", "account_id", firstSegment},
		{"accounts", "account_id", firstSegment},
		{"customer", "customer_id", firstSegment},
		{"customers", "customer_id", firstSegment},
		{"order", "order_id", firstSegment},
		{"orders", "order_id", firstSegment},
		{"product", "product_id", firstSegment},
		{"products", "product_id", firstSegment},
		{"post", "post_id", firstSegment},
		{"posts", "post_id", firstSegment},
		{"article", "article_id", firstSegment},
		{"articles", "article_id", firstSegment},
		{"category", "category_id", firstSegment},
		{"categories", "category_id", firstSegment},
		{"image", "image_id", firstSegment},
		{"images", "image_id", firstSegment},
		{"file", "file_id", firstSegment},
		{"files", "file_id", firstSegment},
		{"video", "video_id", firstSegment},
		{"videos", "video_id", firstSegment},
		{"comment", "comment_id", firstSegment},
		{"comments", "comment_id", firstSegment},
		{"group", "group_id", firstSegment},
		{"groups", "group_id", firstSegment},
		{"team", "team_id", firstSegment},
		{"teams", "team_id", firstSegment},
		{"org", "org_id", firstSegment},
		{"orgs", "org_id", firstSegment},
		{"organization", "org_id", firstSegment},
		{"organizations", "org_id", firstSegment},
		{"company", "company_id", firstSegment},
		{"companies", "company_id", firstSegment},
		{"project", "project_id", firstSegment},
		{"projects", "project_id", firstSegment},
		{"repo", "repo_id", firstSegment},
		{"repos", "repo_id", firstSegment},
		{"branch", "branch", firstSegment},
		{"commit", "commit_hash", firstSegment},
		{"tag", "tag", firstSegment},
		{"release", "release_id", firstSegment},
		{"releases", "release_id", firstSegment},
		{"page", "page_id", firstSegment},
		{"pages", "page_id", firstSegment},
		{"event", "event_id", firstSegment},
		{"events", "event_id", firstSegment},
		{"ticket", "ticket_id", firstSegment},
		{"tickets", "ticket_id", firstSegment},
		{"invoice", "invoice_id", firstSegment},
		{"invoices", "invoice_id", firstSegment},
		{"payment", "payment_id", firstSegment},
		{"payments", "payment_id", firstSegment},
		{"transaction", "transaction_id", firstSegment},
		{"transactions", "transaction_id", firstSegment},
		{"session", "session_id", firstSegment},
		{"sessions", "session_id", firstSegment},
		{"token", "token", firstSegment},
		{"tokens", "token", firstSegment},
		{"key", "api_key", firstSegment},
		{"keys", "api_key", firstSegment},
		{"device", "device_id", firstSegment},
		{"devices", "device_id", firstSegment},
		{"node", "node_id", firstSegment},
		{"nodes", "node_id", firstSegment},
		{"widget", "widget_id", firstSegment},
		{"widgets", "widget_id", firstSegment},
		{"location", "location_id", firstSegment},
		{"locations", "location_id", firstSegment},
		{"store", "store_id", firstSegment},
		{"stores", "store_id", firstSegment},
		{"warehouse", "warehouse_id", firstSegment},
		{"warehouses", "warehouse_id", firstSegment},
		{"variant", "variant_id", firstSegment},
		{"variants", "variant_id", firstSegment},
		{"item", "item_id", firstSegment},
		{"items", "item_id", firstSegment},
		{"role", "role_id", firstSegment},
		{"roles", "role_id", firstSegment},
		{"permission", "permission_id", firstSegment},
		{"permissions", "permission_id", firstSegment},
	}
)

func firstSegment(seg string) string {
	return seg
}

func extractPathParams(rawURL string) []PathParam {
	var params []PathParam

	// Remove scheme and host, keep path only
	path := rawURL
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		afterScheme := rawURL[idx+3:]
		if slashIdx := strings.Index(afterScheme, "/"); slashIdx >= 0 {
			path = afterScheme[slashIdx:]
		} else {
			return nil
		}
	}

	// Remove query string
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}

	if path == "" || path == "/" {
		return nil
	}

	segments := strings.Split(strings.Trim(path, "/"), "/")
	seen := make(map[string]bool)

	for i, seg := range segments {
		if seg == "" || seen[seg] {
			continue
		}

		// Numeric ID
		if reNumericPath.MatchString(seg) {
			name := "id"
			if i > 0 {
				// Use previous segment as context
				prev := strings.ToLower(segments[i-1])
				name = inferParamName(prev, "id")
			}
			params = append(params, PathParam{
				Name:  name,
				Value: seg,
				Type:  "numeric",
			})
			seen[seg] = true
			continue
		}

		// UUID
		if reUUIDPath.MatchString(strings.ToLower(seg)) {
			name := "uuid"
			if i > 0 {
				prev := strings.ToLower(segments[i-1])
				name = inferParamName(prev, "uuid")
			}
			params = append(params, PathParam{
				Name:  name,
				Value: seg,
				Type:  "uuid",
			})
			seen[seg] = true
			continue
		}

		// Hex hash
		if reHexPath.MatchString(seg) {
			name := "hash"
			if i > 0 {
				prev := strings.ToLower(segments[i-1])
				name = inferParamName(prev, "hash")
			}
			params = append(params, PathParam{
				Name:  name,
				Value: seg,
				Type:  "hash",
			})
			seen[seg] = true
			continue
		}

		// Year (date context)
		if reYearPath.MatchString(seg) && i > 0 {
			params = append(params, PathParam{
				Name:  "year",
				Value: seg,
				Type:  "year",
			})
			seen[seg] = true
			continue
		}

		// Locale
		if reLocalePath.MatchString(seg) && i > 0 {
			params = append(params, PathParam{
				Name:  "locale",
				Value: seg,
				Type:  "locale",
			})
			seen[seg] = true
			continue
		}

		// Base64-like token (long, random-looking)
		if reBase64Path.MatchString(seg) && len(seg) > 15 {
			// Only if it looks like a token (not just a slug)
			if hasMixedCase(seg) {
				name := "token"
				if i > 0 {
					prev := strings.ToLower(segments[i-1])
					name = inferParamName(prev, "token")
				}
				params = append(params, PathParam{
					Name:  name,
					Value: seg,
					Type:  "token",
				})
				seen[seg] = true
				continue
			}
		}

		// Known API prefix pattern (e.g., /api/user/123)
		if i > 0 && isKnownIDValue(seg) {
			prev := strings.ToLower(segments[i-1])
			for _, kp := range knownAPIPatterns {
				if prev == kp.prefix {
					params = append(params, PathParam{
						Name:  kp.param,
						Value: seg,
						Type:  inferSegmentType(seg),
					})
					seen[seg] = true
					break
				}
			}
			continue
		}
	}

	return params
}

func inferParamName(context, fallback string) string {
	context = strings.ToLower(context)
	// Map common context words to param names
	mapping := map[string]string{
		"api": "version",
		"v1": "version", "v2": "version", "v3": "version",
		"v4": "version", "v5": "version",
	}
	if name, ok := mapping[context]; ok {
		return name
	}
	// If context ends with 's' (plural), singularize and add _id
	if strings.HasSuffix(context, "s") {
		singular := strings.TrimSuffix(context, "s")
		return singular + "_" + fallback
	}
	return context + "_" + fallback
}

func inferSegmentType(seg string) string {
	if reNumericPath.MatchString(seg) {
		return "numeric"
	}
	if reUUIDPath.MatchString(strings.ToLower(seg)) {
		return "uuid"
	}
	if reHexPath.MatchString(seg) {
		return "hash"
	}
	if reYearPath.MatchString(seg) {
		return "year"
	}
	if reSlugPath.MatchString(seg) {
		return "slug"
	}
	return "string"
}

func isKnownIDValue(seg string) bool {
	// true/false are not IDs
	if seg == "true" || seg == "false" || seg == "null" || seg == "undefined" {
		return false
	}
	// Must look like an identifier
	return reNumericPath.MatchString(seg) ||
		reUUIDPath.MatchString(strings.ToLower(seg)) ||
		reHexPath.MatchString(seg) ||
		(len(seg) >= 6 && reSlugPath.MatchString(seg))
}

func hasMixedCase(s string) bool {
	hasUpper := false
	hasLower := false
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
	}
	return hasUpper && hasLower
}

func paramCountForPath(path string) int {
	_, segCount := relevantPathSegments(path)
	return segCount
}

func relevantPathSegments(path string) (string, int) {
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, "/"), len(nonEmpty)
}

func detectPathTemplate(urls []string) map[string]int {
	templates := make(map[string]int)
	for _, u := range urls {
		path := u
		if idx := strings.Index(u, "://"); idx >= 0 {
			afterScheme := u[idx+3:]
			if slashIdx := strings.Index(afterScheme, "/"); slashIdx >= 0 {
				path = afterScheme[slashIdx:]
			} else {
				continue
			}
		}
		if idx := strings.Index(path, "?"); idx >= 0 {
			path = path[:idx]
		}
		segments := strings.Split(strings.Trim(path, "/"), "/")
		templated := make([]string, len(segments))
		for i, seg := range segments {
			if reNumericPath.MatchString(seg) ||
				reUUIDPath.MatchString(strings.ToLower(seg)) ||
				reHexPath.MatchString(seg) ||
				(len(seg) > 15 && hasMixedCase(seg)) {
				templated[i] = "{param}"
			} else {
				templated[i] = seg
			}
		}
		tmpl := "/" + strings.Join(templated, "/")
		templates[tmpl]++
	}
	return templates
}

// FindPathBasedParams identifies path segments that look like parameters
// and returns them as findings
func findPathBasedFindings(domain string, allResults []DiscoResult) []Finding {
	var findings []Finding

	// First, detect common URL templates
	templates := detectPathTemplate(extractAllURLs(allResults))

	// Then, for each result with path params, emit findings
	for _, r := range allResults {
		if len(r.PathParams) == 0 {
			continue
		}
		for _, pp := range r.PathParams {
			findings = append(findings, Finding{
				Type:        "path_param",
				Category:    "Path Parameter",
				Param:       pp.Name,
				URL:         r.URL,
				Description: "Path-based parameter: " + pp.Name + "=" + truncateString(pp.Value, 40) + " (type: " + pp.Type + ")",
				Severity:    SeverityInfo,
			})
		}
	}

	// Report template patterns (useful for API discovery)
	for tmpl, count := range templates {
		if count >= 2 && strings.Contains(tmpl, "{param}") {
			findings = append(findings, Finding{
				Type:        "api_template",
				Category:    "API URL Template",
				Description: "URL template (seen " + strconv.Itoa(count) + "x): " + tmpl,
				Severity:    SeverityInfo,
			})
		}
	}

	return findings
}

func extractAllURLs(results []DiscoResult) []string {
	urls := make([]string, len(results))
	for i, r := range results {
		urls[i] = r.URL
	}
	return urls
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
