package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type DeepExtractResult struct {
	WebpackChunks    []ExtractedString
	GraphQLQueries   []ExtractedString
	SWCacheURLs      []ExtractedString
	ConsoleURLs      []ExtractedString
	ImportMapURLs    []ExtractedString
	InlineWasmURLs   []ExtractedString
	JSONPEndpoints   []ExtractedString
	SRIIntegrity     []ExtractedString
	MinifiedHints    []ExtractedString
	BootstrapConfigs []ExtractedString
}

var (
	webpackChunkMap   = regexp.MustCompile(`["'\` + "`" + `](\w[\w\-.]*)["'\` + "`" + `]\s*:\s*["'\` + "`" + `]([^"'\` + "`" + `]+\.(?:js|css|json))["'\` + "`" + `]`)
	webpackJSONPPush  = regexp.MustCompile(`(?:self|window|globalThis)\s*\[\s*["'\` + "`" + `]webpackChunk`)
	gqlTemplatePat    = regexp.MustCompile("(?i)(?:gql|graphql)\\s*`")
	gqlQueryName      = regexp.MustCompile(`(?i)(?:query|mutation|subscription)\s+(\w+)`)
	swCacheAddAll     = regexp.MustCompile(`cache\s*\.\s*(?:addAll|add)\s*\(\s*\[([^\]]+)\]`)
	swCacheURLStr     = regexp.MustCompile(`["'\` + "`" + `]([^"'\` + "`" + `,]+)["'\` + "`" + `]`)
	swCachesOpen      = regexp.MustCompile(`caches\s*\.\s*open\s*\(`)
	consoleURL        = regexp.MustCompile(`console\s*\.\s*(?:log|warn|error|info|debug)\s*\([^)]*(https?://[^"'\` + "`" + `,)]+)[^)]*\)`)
	importMapJSON     = regexp.MustCompile(`(?i)["'\` + "`" + `]?\s*imports\s*["'\` + "`" + `]?\s*:\s*\{`)
	importMapEntry    = regexp.MustCompile(`["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*:\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	wasmFetchPat      = regexp.MustCompile(`(?i)(?:WebAssembly|Wasm)\s*\.\s*(?:instantiateStreaming|compileStreaming)\s*\(\s*(?:fetch\s*\(\s*)?["'\` + "`" + `]([^"'\` + "`" + `\)]+)["'\` + "`" + `]`)
	wasmURLPat        = regexp.MustCompile(`(?i)["'\` + "`" + `]([^"'\` + "`" + `]+\.wasm)["'\` + "`" + `]`)
	jsonpCallbackURL  = regexp.MustCompile(`(?i)(?:callback|jsonp)\s*[=:]\s*["'\` + "`" + `]?(\w+)["'\` + "`" + `]?[&\s]`)
	jsonpEndpoint     = regexp.MustCompile(`["'\` + "`" + `]([^"'\` + "`" + `\s]*(?:jsonp|callback)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)
	sriIntegrityPat   = regexp.MustCompile(`integrity\s*=\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	minifiedVarURL    = regexp.MustCompile(`(?m)^\s*(?:var|let|const)\s+(\w{1,3})\s*=\s*["'\` + "`" + `](https?://[^"'\` + "`" + `\s]+)["'\` + "`" + `]\s*$`)
	minifiedVarRel    = regexp.MustCompile(`(?m)^\s*(?:var|let|const)\s+(\w{1,3})\s*=\s*["'\` + "`" + `](/[^"'\` + "`" + `\s]{5,})["'\` + "`" + `]\s*$`)
	bootstrapScript   = regexp.MustCompile(`<script[^>]*id\s*=\s*["'\` + "`" + `](__[A-Z_]+__|__[A-Z_]+)["'\` + "`" + `][^>]*type\s*=\s*["'\` + "`" + `]application/json["'\` + "`" + `][^>]*>([\s\S]{10,}?)</script>`)
	nuxtSSR           = regexp.MustCompile(`window\.__NUXT__\s*=\s*(\{[\s\S]{10,}?\});`)
	apolloSSR         = regexp.MustCompile(`window\.__APOLLO_STATE__\s*=\s*(\{[\s\S]{10,}?\});`)
	relaySSR          = regexp.MustCompile(`window\.__RELAY_DATA__\s*=\s*(\{[\s\S]{10,}?\});`)
	remixSSR          = regexp.MustCompile(`window\.__remixContext\s*=\s*(\{[\s\S]{10,}?\});`)
	angularSSR        = regexp.MustCompile(`window\.__INITIAL_STATE__\s*=\s*(\{[\s\S]{10,}?\});`)
	sveltekitSSR      = regexp.MustCompile(`__SVELTEKIT_DATA__\s*=\s*(\{[\s\S]{10,}?\});`)
	qwikSSR           = regexp.MustCompile(`window\.__QWIK__\s*=\s*(\{[\s\S]{10,}?\});`)
	solidSSR          = regexp.MustCompile(`window\.__SOLID_START__\s*=\s*(\{[\s\S]{10,}?\});`)
)

func performDeepExtraction(body string, sourceURL string) DeepExtractResult {
	var result DeepExtractResult
	seen := make(map[string]bool)

	addURL := func(val, ctx string, isURL, isPath bool) ExtractedString {
		return ExtractedString{Value: val, Context: ctx, IsURL: isURL, IsPath: isPath}
	}

	if webpackJSONPPush.MatchString(body) {
		for _, m := range webpackChunkMap.FindAllStringSubmatch(body, -1) {
			if len(m) >= 3 && !seen[m[2]] {
				seen[m[2]] = true
				result.WebpackChunks = append(result.WebpackChunks, addURL(m[2], "webpack_chunk", strings.HasPrefix(m[2], "http"), strings.HasPrefix(m[2], "/")))
			}
		}
	}

	for _, m := range gqlTemplatePat.FindAllString(body, -1) {
		for _, qm := range gqlQueryName.FindAllStringSubmatch(m, -1) {
			if len(qm) >= 2 && !seen[qm[1]] {
				seen[qm[1]] = true
				result.GraphQLQueries = append(result.GraphQLQueries, addURL(qm[1], "gql_operation", false, false))
			}
		}
	}

	if swCachesOpen.MatchString(body) || strings.Contains(body, "cache.add") {
		for _, cm := range swCacheAddAll.FindAllStringSubmatch(body, -1) {
			if len(cm) >= 2 {
				for _, um := range swCacheURLStr.FindAllStringSubmatch(cm[1], -1) {
					if len(um) >= 2 {
						val := strings.TrimSpace(um[1])
						if val != "" && !seen[val] && len(val) >= 3 {
							seen[val] = true
							result.SWCacheURLs = append(result.SWCacheURLs, addURL(val, "sw_cache", strings.HasPrefix(val, "http"), strings.HasPrefix(val, "/")))
						}
					}
				}
			}
		}
	}

	for _, m := range consoleURL.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.ConsoleURLs = append(result.ConsoleURLs, addURL(m[1], "console_log", strings.HasPrefix(m[1], "http"), strings.HasPrefix(m[1], "/")))
		}
	}

	if importMapJSON.MatchString(body) {
		for _, m := range importMapEntry.FindAllStringSubmatch(body, -1) {
			if len(m) >= 3 && !seen[m[2]] {
				seen[m[2]] = true
				result.ImportMapURLs = append(result.ImportMapURLs, addURL(m[2], "importmap:"+m[1], strings.HasPrefix(m[2], "http"), strings.HasPrefix(m[2], "/")))
			}
		}
	}

	for _, m := range wasmFetchPat.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.InlineWasmURLs = append(result.InlineWasmURLs, addURL(m[1], "wasm_fetch", strings.HasPrefix(m[1], "http"), strings.HasPrefix(m[1], "/")))
		}
	}
	for _, m := range wasmURLPat.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.InlineWasmURLs = append(result.InlineWasmURLs, addURL(m[1], "wasm_url", strings.HasPrefix(m[1], "http"), strings.HasPrefix(m[1], "/")))
		}
	}

	for _, m := range jsonpCallbackURL.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.JSONPEndpoints = append(result.JSONPEndpoints, addURL(m[1], "jsonp_callback", false, false))
		}
	}
	for _, m := range jsonpEndpoint.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.JSONPEndpoints = append(result.JSONPEndpoints, addURL(m[1], "jsonp_endpoint", strings.HasPrefix(m[1], "http"), strings.HasPrefix(m[1], "/")))
		}
	}

	for _, m := range sriIntegrityPat.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && !seen[m[1]] {
			seen[m[1]] = true
			result.SRIIntegrity = append(result.SRIIntegrity, addURL(m[1], "sri_hash", false, false))
		}
	}

	for _, m := range minifiedVarURL.FindAllStringSubmatch(body, -1) {
		if len(m) >= 3 && !seen[m[2]] {
			seen[m[2]] = true
			result.MinifiedHints = append(result.MinifiedHints, addURL(m[2], "minified_var:"+m[1], true, false))
		}
	}
	for _, m := range minifiedVarRel.FindAllStringSubmatch(body, -1) {
		if len(m) >= 3 && !seen[m[2]] {
			seen[m[2]] = true
			result.MinifiedHints = append(result.MinifiedHints, addURL(m[2], "minified_var:"+m[1], false, true))
		}
	}

	for _, m := range bootstrapScript.FindAllStringSubmatch(body, -1) {
		if len(m) >= 3 && !seen[m[1]] {
			seen[m[1]] = true
			result.BootstrapConfigs = append(result.BootstrapConfigs, addURL(m[1], "ssr_script:"+fmt.Sprintf("%d", len(m[2])), false, false))
		}
		if len(m) >= 3 {
			var data interface{}
			if err := json.Unmarshal([]byte(m[2]), &data); err == nil {
				extractURLFromJSON(data, &result.BootstrapConfigs, seen)
			}
		}
	}

	ssrPatterns := []struct {
		re   *regexp.Regexp
		name string
	}{
		{nuxtSSR, "__NUXT__"}, {apolloSSR, "__APOLLO_STATE__"}, {relaySSR, "__RELAY_DATA__"},
		{remixSSR, "__remixContext"}, {angularSSR, "__INITIAL_STATE__"},
		{sveltekitSSR, "__SVELTEKIT_DATA__"}, {qwikSSR, "__QWIK__"}, {solidSSR, "__SOLID_START__"},
	}
	for _, sp := range ssrPatterns {
		for _, m := range sp.re.FindAllStringSubmatch(body, -1) {
			if len(m) >= 2 && !seen[sp.name] {
				seen[sp.name] = true
				result.BootstrapConfigs = append(result.BootstrapConfigs, addURL(sp.name, "ssr_assign:"+fmt.Sprintf("%d", len(m[1])), false, false))
			}
			if len(m) >= 2 {
				var data interface{}
				if err := json.Unmarshal([]byte(m[1]), &data); err == nil {
					extractURLFromJSON(data, &result.BootstrapConfigs, seen)
				}
			}
		}
	}
	return result
}

func extractURLFromJSON(data interface{}, results *[]ExtractedString, seen map[string]bool) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			if s, ok := val.(string); ok {
				if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://") || strings.HasPrefix(s, "//")) && !seen[s] {
					seen[s] = true
					*results = append(*results, ExtractedString{Value: s, Context: "ssr_json:" + key, IsURL: strings.HasPrefix(s, "http") || strings.HasPrefix(s, "//"), IsPath: strings.HasPrefix(s, "/")})
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
