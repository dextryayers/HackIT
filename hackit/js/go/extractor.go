package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ============================================================================
// Advanced JS Extraction Engine — 10 deep extraction modules
// ============================================================================

// DeepExtractResult holds all findings from the deep extraction pass
type DeepExtractResult struct {
	WebpackChunks    []ExtractedString // webpack JSONP chunk URLs
	GraphQLQueries   []ExtractedString // gql`...` and graphql`...` template tags
	SWCacheURLs      []ExtractedString // service worker cache.addAll([...])
	ConsoleURLs      []ExtractedString // console.log('URL: ...')
	ImportMapURLs    []ExtractedString // <script type="importmap"> module URLs
	InlineWasmURLs   []ExtractedString // WebAssembly.instantiate('...')
	JSONPEndpoints   []ExtractedString // JSONP callback endpoints
	SRIIntegrity     []ExtractedString // integrity="sha384-..." CDN resources
	MinifiedHints    []ExtractedString // minified variable heuristic URLs
	BootstrapConfigs []ExtractedString // SSR bootstrap inline JSON
}

var (
	// ── 1. Webpack chunk map ──
	// Matches webpack JSONP bundle's module map containing chunk URLs
	// Typical pattern: e[r] = "...chunkhash.js"
	webpackChunkURL = regexp.MustCompile(`["'\` + "`" + `]([^"'\` + "`" + `]+\.(?:js|css|json))["'\` + "`" + `]\s*[}\]]\s*[,;]`)
	// Webpack chunk ID → filename mapping: "chunk-id":"chunk-filename.js"
	webpackChunkMap = regexp.MustCompile(`["'\` + "`" + `](\w[\w\-.]*)["'\` + "`" + `]\s*:\s*["'\` + "`" + `]([^"'\` + "`" + `]+\.(?:js|css|json))["'\` + "`" + `]`)
	// Webpack JSONP array: self["webpackChunk_"].push([["chunkId"],{"moduleId":...}])
	webpackJSONPPush = regexp.MustCompile(`(?:self|window|globalThis)\s*\[\s*["'\` + "`" + `]webpackChunk`)

	// ── 2. GraphQL template literals ──
	// Tagged template literals: gql`...`, graphql`...`
	gqlTemplatePat = regexp.MustCompile("(?i)(?:gql|graphql)\\s*`")
	// Extract query/mutation/subscription names from GQL templates
	gqlQueryName = regexp.MustCompile(`(?i)(?:query|mutation|subscription)\s+(\w+)`)
	// GraphQL endpoint references: "https://api.example.com/graphql"
	gqlEndpointInStr = regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:graphql|gql|query|v1/graphql)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)

	// ── 3. Service Worker cache ──
	// cache.addAll(['/url1', '/url2', ...]) or cache.add('/url')
	swCacheAddAll = regexp.MustCompile(`cache\s*\.\s*(?:addAll|add)\s*\(\s*\[([^\]]+)\]`)
	// Individual URL strings inside cache.addAll array
	swCacheURLStr = regexp.MustCompile(`["'\` + "`" + `]([^"'\` + "`" + `,]+)["'\` + "`" + `]`)
	// caches.open('cache-name').then(cache => cache.addAll(['/url1']))
	swCachesOpen = regexp.MustCompile(`caches\s*\.\s*open\s*\(`)

	// ── 4. Console.log URLs ──
	consoleURL = regexp.MustCompile(`console\s*\.\s*(?:log|warn|error|info|debug)\s*\([^)]*(https?://[^"'\` + "`" + `,)]+)[^)]*\)`)

	// ── 5. Import Map (ESM) ──
	// importmap JSON inline: {"imports":{"module":"https://cdn.com/mod.js"}}
	importMapJSON = regexp.MustCompile(`(?i)["'\` + "`" + `]?\s*imports\s*["'\` + "`" + `]?\s*:\s*\{`)
	importMapEntry = regexp.MustCompile(`["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*:\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)

	// ── 6. Inline WASM ──
	// WebAssembly.instantiate(new Uint8Array([...]) or fetch('module.wasm')
	wasmFetchPat = regexp.MustCompile(`(?i)(?:WebAssembly|Wasm)\s*\.\s*(?:instantiateStreaming|compileStreaming)\s*\(\s*(?:fetch\s*\(\s*)?["'\` + "`" + `]([^"'\` + "`" + `\)]+)["'\` + "`" + `]`)
	// WASM URL in new WebAssembly.Module(...)
	wasmURLPat = regexp.MustCompile(`(?i)["'\` + "`" + `]([^"'\` + "`" + `]+\.wasm)["'\` + "`" + `]`)

	// ── 7. JSONP callback ──
	// JSONP: callback=handleResponse&url=https://...
	jsonpCallbackURL = regexp.MustCompile(`(?i)(?:callback|jsonp)\s*[=:]\s*["'\` + "`" + `]?(\w+)["'\` + "`" + `]?[&\s]`)
	// JSONP endpoint: url += '?callback=jsonp' + ...
	jsonpEndpoint = regexp.MustCompile(`["'\` + "`" + `]([^"'\` + "`" + `\s]*(?:jsonp|callback)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)

	// ── 8. SRI integrity ──
	// integrity="sha384-..." or integrity='sha512-...'
	sriIntegrityPat = regexp.MustCompile(`integrity\s*=\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	// crossorigin="anonymous" with src URL
	sriCrossOrigin = regexp.MustCompile(`crossorigin\s*=\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)

	// ── 9. Minified variable heuristic ──
	// Short variable names assigned URL strings: a="https://...", b="/api/..."
	minifiedVarURL = regexp.MustCompile(`(?m)^\s*(?:var|let|const)\s+(\w{1,3})\s*=\s*["'\` + "`" + `](https?://[^"'\` + "`" + `\s]+)["'\` + "`" + `]\s*$`)
	minifiedVarRel = regexp.MustCompile(`(?m)^\s*(?:var|let|const)\s+(\w{1,3})\s*=\s*["'\` + "`" + `](/[^"'\` + "`" + `\s]{5,})["'\` + "`" + `]\s*$`)

	// ── 10. Bootstrap / SSR config ──
	// Script tag with inline JSON: <script id="__NEXT_DATA__" type="application/json">...</script>
	bootstrapScript = regexp.MustCompile(`<script[^>]*id\s*=\s*["'\` + "`" + `](__[A-Z_]+__|__[A-Z_]+)["'\` + "`" + `][^>]*type\s*=\s*["'\` + "`" + `]application/json["'\` + "`" + `][^>]*>([\s\S]{10,}?)</script>`)
	// Vue SSR: window.__NUXT__ = { ... }
	nuxtSSR = regexp.MustCompile(`window\.__NUXT__\s*=\s*(\{[\s\S]{10,}?\});`)
	// Apollo: window.__APOLLO_STATE__ = { ... }
	apolloSSR = regexp.MustCompile(`window\.__APOLLO_STATE__\s*=\s*(\{[\s\S]{10,}?\});`)
	// React Relay: window.__RELAY_DATA__ = { ... }
	relaySSR = regexp.MustCompile(`window\.__RELAY_DATA__\s*=\s*(\{[\s\S]{10,}?\});`)
	// Remix: window.__remixContext = { ... }
	remixSSR = regexp.MustCompile(`window\.__remixContext\s*=\s*(\{[\s\S]{10,}?\});`)
	// Angular Universal: window.__INITIAL_STATE__ = { ... }
	angularSSR = regexp.MustCompile(`window\.__INITIAL_STATE__\s*=\s*(\{[\s\S]{10,}?\});`)
	// SvelteKit: <script>__SVELTEKIT_DATA__ = { ... }</script>
	sveltekitSSR = regexp.MustCompile(`__SVELTEKIT_DATA__\s*=\s*(\{[\s\S]{10,}?\});`)
	// Qwik: window.__QWIK__ = { ... }
	qwikSSR = regexp.MustCompile(`window\.__QWIK__\s*=\s*(\{[\s\S]{10,}?\});`)
	// SolidStart: window.__SOLID_START__ = { ... }
	solidSSR = regexp.MustCompile(`window\.__SOLID_START__\s*=\s*(\{[\s\S]{10,}?\});`)
)

// performDeepExtraction runs all 10 extraction modules on JS/HTML source
func performDeepExtraction(body string, sourceURL string) DeepExtractResult {
	var result DeepExtractResult
	seen := make(map[string]bool)

	addURL := func(val, ctx string, isURL, isPath bool) ExtractedString {
		return ExtractedString{Value: val, Context: ctx, IsURL: isURL, IsPath: isPath}
	}

	// ── 1. Webpack chunk extraction ──
	if webpackJSONPPush.MatchString(body) {
		for _, m := range webpackChunkMap.FindAllStringSubmatch(body, -1) {
			if len(m) >= 3 && !seen[m[2]] {
				seen[m[2]] = true
				result.WebpackChunks = append(result.WebpackChunks,
					addURL(m[2], "webpack_chunk", strings.HasPrefix(m[2], "http"), strings.HasPrefix(m[2], "/")))
			}
		}
	}

	// ── 2. GraphQL queries ──
	// Find gql`...` template content and extract operation names + URLs
	for _, m := range gqlTemplatePat.FindAllString(body, -1) {
		// Extract query/mutation/subscription names from the template content
		for _, qm := range gqlQueryName.FindAllStringSubmatch(m, -1) {
			if len(qm) >= 2 {
				name := qm[1]
				if !seen[name] {
					seen[name] = true
					result.GraphQLQueries = append(result.GraphQLQueries,
						addURL(name, "gql_operation", false, false))
				}
			}
		}
		// Extract endpoint URLs from within gql templates
		for _, em := range gqlEndpointInStr.FindAllStringSubmatch(m, -1) {
			if len(em) >= 2 && !seen[em[1]] {
				seen[em[1]] = true
				result.GraphQLQueries = append(result.GraphQLQueries,
					addURL(em[1], "gql_endpoint", true, false))
			}
		}
	}

	// ── 3. Service Worker cache ──
	if swCachesOpen.MatchString(body) || strings.Contains(body, "cache.add") {
		for _, cm := range swCacheAddAll.FindAllStringSubmatch(body, -1) {
			if len(cm) >= 2 {
				arrayContent := cm[1]
				for _, um := range swCacheURLStr.FindAllStringSubmatch(arrayContent, -1) {
					if len(um) >= 2 {
						val := strings.TrimSpace(um[1])
						if val != "" && !seen[val] && len(val) >= 3 {
							seen[val] = true
							result.SWCacheURLs = append(result.SWCacheURLs,
								addURL(val, "sw_cache",
									strings.HasPrefix(val, "http"), strings.HasPrefix(val, "/")))
						}
					}
				}
			}
		}
	}

	// ── 4. Console.log URLs ──
	for _, m := range consoleURL.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.ConsoleURLs = append(result.ConsoleURLs,
				addURL(m[1], "console_log",
					strings.HasPrefix(m[1], "http"), strings.HasPrefix(m[1], "/")))
		}
	}

	// ── 5. Import Map ──
	if importMapJSON.MatchString(body) {
		for _, m := range importMapEntry.FindAllStringSubmatch(body, -1) {
			if len(m) >= 3 {
				moduleName := m[1]
				moduleURL := m[2]
				if !seen[moduleURL] {
					seen[moduleURL] = true
					result.ImportMapURLs = append(result.ImportMapURLs,
						addURL(moduleURL, "importmap:"+moduleName,
							strings.HasPrefix(moduleURL, "http"), strings.HasPrefix(moduleURL, "/")))
				}
			}
		}
	}

	// ── 6. Inline WASM ──
	for _, m := range wasmFetchPat.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.InlineWasmURLs = append(result.InlineWasmURLs,
				addURL(m[1], "wasm_fetch",
					strings.HasPrefix(m[1], "http"), strings.HasPrefix(m[1], "/")))
		}
	}
	for _, m := range wasmURLPat.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.InlineWasmURLs = append(result.InlineWasmURLs,
				addURL(m[1], "wasm_url",
					strings.HasPrefix(m[1], "http"), strings.HasPrefix(m[1], "/")))
		}
	}

	// ── 7. JSONP callback endpoints ──
	for _, m := range jsonpCallbackURL.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.JSONPEndpoints = append(result.JSONPEndpoints,
				addURL(m[1], "jsonp_callback", false, false))
		}
	}
	for _, m := range jsonpEndpoint.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.JSONPEndpoints = append(result.JSONPEndpoints,
				addURL(m[1], "jsonp_endpoint",
					strings.HasPrefix(m[1], "http"), strings.HasPrefix(m[1], "/")))
		}
	}

	// ── 8. SRI integrity ──
	for _, m := range sriIntegrityPat.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.SRIIntegrity = append(result.SRIIntegrity,
				addURL(m[1], "sri_hash", false, false))
		}
	}
	for _, m := range sriCrossOrigin.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.SRIIntegrity = append(result.SRIIntegrity,
				addURL(m[1], "crossorigin", false, false))
		}
	}

	// ── 9. Minified variable heuristic ──
	for _, m := range minifiedVarURL.FindAllStringSubmatch(body, -1) {
		if len(m) >= 3 && !seen[m[2]] {
			seen[m[2]] = true
			result.MinifiedHints = append(result.MinifiedHints,
				addURL(m[2], "minified_var:"+m[1], true, false))
		}
	}
	for _, m := range minifiedVarRel.FindAllStringSubmatch(body, -1) {
		if len(m) >= 3 && !seen[m[2]] {
			seen[m[2]] = true
			result.MinifiedHints = append(result.MinifiedHints,
				addURL(m[2], "minified_var:"+m[1], false, true))
		}
	}

	// ── 10. Bootstrap / SSR config ──
	// Script tag inline JSON
	for _, m := range bootstrapScript.FindAllStringSubmatch(body, -1) {
		if len(m) >= 3 {
			ssrName := m[1]
			payload := m[2]
			if !seen[ssrName] {
				seen[ssrName] = true
				result.BootstrapConfigs = append(result.BootstrapConfigs,
					addURL(ssrName, "ssr_script:"+fmt.Sprintf("%d", len(payload)), false, false))
			}
			// Extract URLs from the embedded JSON
			var data interface{}
			if err := json.Unmarshal([]byte(payload), &data); err == nil {
				extractURLFromJSON(data, &result.BootstrapConfigs, seen)
			}
		}
	}

	// Framework-specific SSR assignments
	ssrPatterns := []struct {
		re    *regexp.Regexp
		name  string
	}{
		{nuxtSSR, "__NUXT__"},
		{apolloSSR, "__APOLLO_STATE__"},
		{relaySSR, "__RELAY_DATA__"},
		{remixSSR, "__remixContext"},
		{angularSSR, "__INITIAL_STATE__"},
		{sveltekitSSR, "__SVELTEKIT_DATA__"},
		{qwikSSR, "__QWIK__"},
		{solidSSR, "__SOLID_START__"},
	}

	for _, sp := range ssrPatterns {
		for _, m := range sp.re.FindAllStringSubmatch(body, -1) {
			if len(m) >= 2 {
				payload := m[1]
				if !seen[sp.name] {
					seen[sp.name] = true
					result.BootstrapConfigs = append(result.BootstrapConfigs,
						addURL(sp.name, "ssr_assign:"+fmt.Sprintf("%d", len(payload)), false, false))
				}
				var data interface{}
				if err := json.Unmarshal([]byte(payload), &data); err == nil {
					extractURLFromJSON(data, &result.BootstrapConfigs, seen)
				}
			}
		}
	}

	return result
}

// extractURLFromJSON recursively walks parsed JSON and extracts URL-like strings
func extractURLFromJSON(data interface{}, results *[]ExtractedString, seen map[string]bool) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			if s, ok := val.(string); ok {
				if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
					strings.HasPrefix(s, "/") || strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://") ||
					strings.HasPrefix(s, "//")) && !seen[s] {
					seen[s] = true
					*results = append(*results, ExtractedString{
						Value:   s,
						Context: "ssr_json:" + key,
						IsURL:   strings.HasPrefix(s, "http") || strings.HasPrefix(s, "//"),
						IsPath:  strings.HasPrefix(s, "/"),
					})
				}
			} else {
				extractURLFromJSON(val, results, seen)
			}
		}
	case []interface{}:
		for _, item := range v {
			extractURLFromJSON(item, results, seen)
		}
	}
}

// extractURLsFromDeepResult returns all URL-like strings from deep extraction
func extractURLsFromDeepResult(result DeepExtractResult) []ExtractedString {
	var urls []ExtractedString
	seen := make(map[string]bool)

	sources := [][]ExtractedString{
		result.WebpackChunks,
		result.GraphQLQueries,
		result.SWCacheURLs,
		result.ConsoleURLs,
		result.ImportMapURLs,
		result.InlineWasmURLs,
		result.JSONPEndpoints,
		result.MinifiedHints,
		result.BootstrapConfigs,
	}

	for _, list := range sources {
		for _, s := range list {
			if (s.IsURL || s.IsPath) && !seen[s.Value] {
				seen[s.Value] = true
				urls = append(urls, s)
			}
		}
	}

	return urls
}
