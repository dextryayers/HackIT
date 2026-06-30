package main

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

var (
	singleQuotedStr = regexp.MustCompile(`'([^'\\]*(?:\\.[^'\\]*)*)'`)
	doubleQuotedStr = regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*)"`)
	backtickStr     = regexp.MustCompile("`([^`\\\\]*(?:\\\\.[^`\\\\]*)*)`")
	urlInStr        = regexp.MustCompile(`(https?://[^\s"'\` + "`" + `,;)]+)`)
	apiPathInStr    = regexp.MustCompile(`(/\w[\w\-./]*(?:api|graphql|rest|v\d|auth|oauth|token|admin|webhook|hook|callback|proxy|upload|download|ws|socket)[\w\-./]*)`)

	concatLeftAbsolute = regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `]+)["'\` + "`" + `]\s*\+`)
	concatLeftRelative = regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `]+/)["'\` + "`" + `]\s*\+`)
	concatLeftKeyword  = regexp.MustCompile(`["'\` + "`" + `]([^"'\` + "`" + `]{4,}(?:api|graphql|rest|s3|cdn|auth|token|admin|service|host|url|base|proxy|ws|socket|endpoint|server|domain|bucket|origin|prefix|path|route))["'\` + "`" + `]\s*\+`)
	concatRight        = regexp.MustCompile(`\+\s*["'\` + "`" + `]([^"'\` + "`" + `]{4,}(?:api|graphql|rest|v\d|auth|oauth|token|admin|webhook|hook|callback|proxy|upload|download|endpoint|path|route|key|id|secret))["'\` + "`" + `]`)

	jsonFieldStr  = regexp.MustCompile(`["'\` + "`" + `]?(\w+)["'\` + "`" + `]?\s*:\s*["'\` + "`" + `]([^"'\` + "`" + `\n]{3,})["'\` + "`" + `]`)
	urlFieldNames = regexp.MustCompile(`(?i)^(?:url|uri|href|src|endpoint|api_url|api_endpoint|base_url|base|host|origin|target|redirect|callback|webhook|proxy|redirect_uri|return_url|postback|notify_url|service_url|server_url|upload_url|download_url|icon|image|avatar|logo|cover|thumbnail|preview|asset|manifest|data_url|action|form_action|link|self|next|prev|first|last|related)$`)

	dynamicImportPat  = regexp.MustCompile(`import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`)
	importAssertPat   = regexp.MustCompile(`import\s+\w+\s+from\s+["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*(?:assert|with)\s*\{`)
	exportFromPat     = regexp.MustCompile(`export\s+(?:\{[^}]*\}|\*\s+as\s+\w+|\w+)?\s*from\s+["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	webpackDynamicImp = regexp.MustCompile(`import\s*\(\s*/\*[\s\S]*?\*/\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`)

	workerPat       = regexp.MustCompile(`new\s+(?:Worker|SharedWorker)\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	swRegisterPat   = regexp.MustCompile(`(?:navigator\.serviceWorker\.register|self\s*\.\s*registration)\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	wasmPat         = regexp.MustCompile(`(?:WebAssembly|Wasm)\s*\.\s*(?:instantiateStreaming|compileStreaming|instantiate|compile)\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	jsPostMessagePat  = regexp.MustCompile(`(?:postMessage|sendMessage)\s*\(\s*[^,]+,\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	windowOpenPat   = regexp.MustCompile(`window\.open\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	locationAssign  = regexp.MustCompile(`location\s*\.\s*(?:assign|replace|href)\s*(?:=\s*["'\` + "`" + `]|\s*\(\s*["'\` + "`" + `])\s*([^"'\` + "`" + `\)]+)["'\` + "`" + `]`)
	routerPushPat   = regexp.MustCompile(`router\s*\.\s*(?:push|replace)\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `\)]+)["'\` + "`" + `]`)

	svelteKitLoadPat = regexp.MustCompile(`export\s+(?:const|function|async\s+function)\s+load\s*[=\(]`)

	cssURLRef    = regexp.MustCompile(`(?i)url\s*\(\s*["'\` + "`" + `]?([^"'\` + "`" + `\)]+)["'\` + "`" + `]?\s*\)`)
	cssImportRef = regexp.MustCompile(`(?i)@import\s+(?:url\s*\()?\s*["'\` + "`" + `]([^"'\` + "`" + `\)]+)["'\` + "`" + `]?\s*(?:\))?`)
)

func stripJSComments(code string) string {
	var out strings.Builder
	out.Grow(len(code))
	i := 0
	for i < len(code) {
		if code[i] == '/' && i+1 < len(code) && code[i+1] == '/' {
			i += 2
			for i < len(code) && code[i] != '\n' {
				i++
			}
			continue
		}
		if code[i] == '/' && i+1 < len(code) && code[i+1] == '*' {
			i += 2
			for i+1 < len(code) && !(code[i] == '*' && code[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}
		if code[i] == '\'' || code[i] == '"' {
			quote := code[i]
			out.WriteByte(quote)
			i++
			for i < len(code) {
				if code[i] == '\\' {
					out.WriteByte(code[i]); i++
					if i < len(code) {
						out.WriteByte(code[i]); i++
					}
					continue
				}
				if code[i] == quote {
					out.WriteByte(quote); i++
					break
				}
				if code[i] == '\n' {
					break
				}
				out.WriteByte(code[i]); i++
			}
			continue
		}
		if code[i] == '`' {
			out.WriteByte('`'); i++
			depth := 0
			for i < len(code) {
				if code[i] == '\\' {
					out.WriteByte(code[i]); i++
					if i < len(code) {
						out.WriteByte(code[i]); i++
					}
					continue
				}
				if code[i] == '`' && depth == 0 {
					out.WriteByte('`'); i++
					break
				}
				if code[i] == '$' && i+1 < len(code) && code[i+1] == '{' {
					depth++
				}
				if code[i] == '}' && depth > 0 {
					depth--
				}
				out.WriteByte(code[i]); i++
			}
			continue
		}
		out.WriteByte(code[i])
		i++
	}
	return out.String()
}

func (c *Crawler) parseJSSource(body string, sourceURL string, depth int) {
	analysis := analyzeJS(body, sourceURL)
	emitAndQueue := func(val, ndjsonType, ctx string) {
		absURL := resolveURL(val, c.BaseURL)
		if absURL == "" {
			return
		}
		key := ndjsonType + ":" + absURL
		c.mu.Lock()
		if c.seenStrings[key] {
			c.mu.Unlock()
			return
		}
		c.seenStrings[key] = true
		c.mu.Unlock()
		writeOutput(`{"type":%q,"url":%q,"source":%q,"ctx":%q}`+"\n", ndjsonType, absURL, sourceURL, ctx)
		if c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
			c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1})
		}
		c.extractSubdomainFromURL(val)
	}

	for _, s := range analysis.Strings {
		emitAndQueue(s.Value, "js_string_url", s.Context)
	}
	for _, s := range analysis.ModuleURLs {
		emitAndQueue(s.Value, "module_url", s.Context)
	}
	for _, s := range analysis.TemplateParts {
		emitAndQueue(s.Value, "template_reconstructed", s.Context)
	}
	for _, s := range analysis.CSSRefs {
		emitAndQueue(s.Value, "css_ref", s.Context)
	}
	for _, s := range analysis.EnvURLs {
		emitAndQueue(s.Value, "env_url", s.Context)
	}
	for _, s := range analysis.Concatenations {
		emitAndQueue(s.Value, "concat_url", s.Context)
	}
	for _, s := range analysis.ConfigObjects {
		emitAndQueue(s.Value, "config_url", s.Context)
	}
	for _, s := range analysis.SvelteKitURLs {
		emitAndQueue(s.Value, "sveltekit_url", s.Context)
	}

	if c.Opts.Endpoints {
		for _, ep := range analysis.Endpoints {
			absURL := resolveURL(ep.URL, c.BaseURL)
			if absURL != "" {
				writeOutput(`{"type":"endpoint","url":%q,"source":%q,"endpoint_type":%q}`+"\n", absURL, sourceURL, ep.Type)
				if c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
					c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1})
				}
			}
		}
	}

	if c.Opts.Secrets {
		for _, f := range analysis.Secrets {
			writeOutput(`{"type":"sensitive","name":%q,"match":%q,"source":%q}`+"\n", f.Name, f.Match, sourceURL)
		}
	}

	deep := performDeepExtraction(body, sourceURL)
	for _, list := range [][]ExtractedString{
		deep.WebpackChunks, deep.GraphQLQueries, deep.SWCacheURLs,
		deep.ConsoleURLs, deep.ImportMapURLs, deep.InlineWasmURLs,
		deep.JSONPEndpoints, deep.MinifiedHints,
	} {
		for _, s := range list {
			if s.IsURL || s.IsPath {
				emitAndQueue(s.Value, "deep_extract", s.Context)
			}
		}
	}

	c.extractSubdomainsFromBody(body, sourceURL)

	if c.Opts.Secrets {
		for _, cm := range findComments(body, sourceURL) {
			writeOutput(`{"type":"comment","comment":%q,"source":%q}`+"\n", cm.Comment, cm.Source)
		}
	}

	if c.Opts.Network {
		c.captureJSNetwork(body, sourceURL, depth)
	}

	c.extractDependencies(body, sourceURL, depth)

	if c.Opts.Sourcemap && depth < c.Scope.MaxDepth {
		c.extractInlineSourceMap(body, sourceURL)
		c.checkSourceMap(sourceURL)
	}
}

func isLikelyURL(s string) bool {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://") || strings.HasPrefix(s, "//") {
		return !strings.ContainsAny(s, " \t\n\r<>") && len(s) > 10
	}
	if strings.HasPrefix(s, "/") {
		if strings.ContainsAny(s, " \t\n\r<>") {
			return false
		}
		sTrimmed := strings.TrimPrefix(s, "/")
		if !strings.Contains(sTrimmed, "/") && !strings.Contains(sTrimmed, ".") && len(sTrimmed) < 5 {
			return false
		}
		if len(s) < 3 {
			return false
		}
		ext := path.Ext(s)
		if ext != "" {
			return true
		}
		keywords := []string{"api", "graphql", "rest", "auth", "oauth", "token", "admin", "webhook", "hook", "callback", "proxy", "upload", "download", "ws", "socket", "endpoint", "v1", "v2", "v3", "v4", "login", "signup", "register", "search", "query", "user", "users", "config", "conf", "settings", "js", "css", "img", "assets", "static", "build", "dist", "app", "main", "bundle", "vendor", "chunk", "page", "pages", "component", "src", "lib", "util", "helper", "test", "spec", ".json", ".js", ".ts", ".html", ".xml", ".yaml", ".yml", ".php", ".asp", ".aspx", ".jsp", ".map"}
		for _, kw := range keywords {
			if strings.Contains(s, kw) {
				return true
			}
		}
		if strings.Count(s, "/") >= 2 {
			return true
		}
		return false
	}
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") {
		return !strings.ContainsAny(s, " \t\n\r<>") && len(s) > 4
	}
	if strings.Contains(s, ".") && !strings.ContainsAny(s, " \t\n\r<>") {
		parts := strings.Split(s, "/")
		if len(parts) >= 2 && strings.Contains(parts[len(parts)-1], ".") {
			return true
		}
	}
	return false
}

func extractAllStrings(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	addStr := func(val, ctx string) {
		val = strings.TrimSpace(val)
		if val == "" || seen[val] || len(val) < 3 || !isLikelyURL(val) {
			return
		}
		seen[val] = true
		results = append(results, ExtractedString{
			Value: val, Context: ctx,
			IsURL:  strings.HasPrefix(val, "http"),
			IsPath: strings.HasPrefix(val, "/"),
		})
	}

	for _, m := range singleQuotedStr.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addStr(m[1], "single")
		}
	}
	for _, m := range doubleQuotedStr.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addStr(m[1], "double")
		}
	}
	for _, m := range backtickStr.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 && !strings.Contains(m[1], "${") {
			addStr(m[1], "template")
		}
	}
	for _, m := range jsonFieldStr.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 3 && urlFieldNames.MatchString(m[1]) {
			addStr(m[2], "json_field")
		}
	}
	templateParts := backtickStr.FindAllString(cleaned, -1)
	for _, t := range templateParts {
		for _, m := range urlInStr.FindAllStringSubmatch(t, -1) {
			if len(m) >= 2 {
				addStr(m[1], "template_url")
			}
		}
		for _, m := range apiPathInStr.FindAllStringSubmatch(t, -1) {
			if len(m) >= 2 {
				addStr(m[1], "template_path")
			}
		}
	}
	return results
}

func extractModernJSModuleURLs(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	addResolved := func(val, ctx string) {
		val = strings.Trim(val, "'\"`")
		val = strings.TrimSpace(val)
		if val == "" || seen[val] || len(val) < 3 {
			return
		}
		seen[val] = true
		results = append(results, ExtractedString{
			Value: val, Context: ctx,
			IsURL:  strings.HasPrefix(val, "http"),
			IsPath: strings.HasPrefix(val, "/") || strings.HasPrefix(val, "./") || strings.HasPrefix(val, "../"),
		})
	}

	for _, m := range dynamicImportPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "dynamic_import")
		}
	}
	for _, m := range webpackDynamicImp.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "webpack_import")
		}
	}
	for _, m := range importAssertPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "import_assert")
		}
	}
	for _, m := range exportFromPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			addResolved(m[1], "export_from")
		}
	}
	return results
}

func extractTemplateLiteralInterpolations(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)
	interpRe := regexp.MustCompile(`\$\{[^}]+\}`)

	templateParts := backtickStr.FindAllString(cleaned, -1)
	for _, t := range templateParts {
		parts := interpRe.Split(t, -1)
		if len(parts) < 2 {
			continue
		}
		reconstructed := strings.Join(parts, "")
		reconstructed = strings.Trim(reconstructed, "` \t\n\r")
		if reconstructed == "" || seen[reconstructed] || len(reconstructed) < 5 {
			continue
		}
		seen[reconstructed] = true
		isURL := strings.HasPrefix(reconstructed, "http")
		isPath := strings.HasPrefix(reconstructed, "/")
		if isURL || isPath {
			results = append(results, ExtractedString{Value: reconstructed, Context: "template_reconstructed", IsURL: isURL, IsPath: isPath})
		}
		for _, part := range parts {
			part = strings.Trim(part, "` \t\n\r")
			if part == "" || len(part) < 5 || seen[part] {
				continue
			}
			pIsURL := strings.HasPrefix(part, "http")
			pIsPath := strings.HasPrefix(part, "/")
			if pIsURL || pIsPath {
				seen[part] = true
				results = append(results, ExtractedString{Value: part, Context: "template_part", IsURL: pIsURL, IsPath: pIsPath})
			}
		}
	}
	return results
}

func extractCSSReferences(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)
	templateParts := backtickStr.FindAllString(cleaned, -1)
	for _, t := range templateParts {
		for _, m := range cssURLRef.FindAllStringSubmatch(t, -1) {
			if len(m) >= 2 {
				val := strings.TrimSpace(m[1])
				if val != "" && !seen[val] && len(val) >= 3 {
					seen[val] = true
					isURL := strings.HasPrefix(val, "http")
					isPath := strings.HasPrefix(val, "/") || strings.HasPrefix(val, "data:")
					if isURL || isPath {
						results = append(results, ExtractedString{Value: val, Context: "css_url", IsURL: isURL, IsPath: isPath})
					}
				}
			}
		}
		for _, m := range cssImportRef.FindAllStringSubmatch(t, -1) {
			if len(m) >= 2 {
				val := strings.TrimSpace(m[1])
				if val != "" && !seen[val] && len(val) >= 3 {
					seen[val] = true
					isURL := strings.HasPrefix(val, "http")
					isPath := strings.HasPrefix(val, "/") || strings.HasPrefix(val, "./") || strings.HasPrefix(val, "../")
					if isURL || isPath {
						results = append(results, ExtractedString{Value: val, Context: "css_import", IsURL: isURL, IsPath: isPath})
					}
				}
			}
		}
	}
	return results
}

func extractEnvironmentURLs(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)
	add := func(val, ctx string) {
		val = strings.Trim(val, "'\"`")
		val = strings.TrimSpace(val)
		if val == "" || seen[val] || len(val) < 3 {
			return
		}
		seen[val] = true
		results = append(results, ExtractedString{Value: val, Context: ctx, IsURL: strings.HasPrefix(val, "http"), IsPath: strings.HasPrefix(val, "/") || strings.HasPrefix(val, "./") || strings.HasPrefix(val, "../")})
	}
	for _, m := range workerPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			add(m[1], "worker")
		}
	}
	for _, m := range swRegisterPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			add(m[1], "service_worker")
		}
	}
	for _, m := range wasmPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			add(m[1], "wasm")
		}
	}
	for _, m := range jsPostMessagePat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			add(m[1], "postmessage_origin")
		}
	}
	for _, m := range windowOpenPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			add(m[1], "window_open")
		}
	}
	for _, m := range locationAssign.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			add(m[1], "location_assign")
		}
	}
	for _, m := range routerPushPat.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			add(m[1], "router_push")
		}
	}
	return results
}

func extractConcatenationPatterns(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)
	add := func(val, ctx string, isURL, isPath bool) {
		if val != "" && !seen[val] {
			seen[val] = true
			results = append(results, ExtractedString{Value: val, Context: ctx, IsURL: isURL, IsPath: isPath})
		}
	}
	for _, m := range concatLeftAbsolute.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			add(strings.TrimSpace(m[1]), "concat_left_abs", true, false)
		}
	}
	for _, m := range concatLeftRelative.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			add(strings.TrimSpace(m[1]), "concat_left_rel", false, true)
		}
	}
	for _, m := range concatLeftKeyword.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := strings.TrimSpace(m[1])
			add(val, "concat_left_keyword", strings.HasPrefix(val, "http"), strings.HasPrefix(val, "/"))
		}
	}
	for _, m := range concatRight.FindAllStringSubmatch(cleaned, -1) {
		if len(m) >= 2 {
			val := strings.TrimSpace(m[1])
			add(val, "concat_right", strings.HasPrefix(val, "http"), strings.HasPrefix(val, "/"))
		}
	}
	return results
}

func extractJSONConfigObjects(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	var results []ExtractedString
	seen := make(map[string]bool)

	objStarts := findAllObjAssignments(cleaned)
	for _, startPos := range objStarts {
		endPos := findMatchingBrace(cleaned, startPos)
		if endPos <= startPos {
			continue
		}
		objStr := cleaned[startPos : endPos+1]
		objStr = strings.ReplaceAll(objStr, `'`, `"`)
		keyRe := regexp.MustCompile(`([{,]\s*)(\w+)\s*:`)
		objStr = keyRe.ReplaceAllString(objStr, `$1"$2":`)
		objStr = regexp.MustCompile(`,(\s*[}\]])`).ReplaceAllString(objStr, "$1")

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(objStr), &parsed); err == nil {
			extractStringsFromParsed(parsed, &results, seen, "")
		}
	}
	return results
}

func findAllObjAssignments(code string) []int {
	var positions []int
	pat := regexp.MustCompile(`(?:const|let|var|static|return|=\s*)\s+\w*\s*=\s*\{`)
	for _, idx := range pat.FindAllStringIndex(code, -1) {
		if idx[1] > 0 && idx[1] < len(code) {
			if bracePos := strings.LastIndex(code[:idx[1]], "{"); bracePos >= 0 {
				positions = append(positions, bracePos)
			}
		}
	}
	arrowObjPat := regexp.MustCompile(`=>\s*\{`)
	for _, idx := range arrowObjPat.FindAllStringIndex(code, -1) {
		if bracePos := strings.LastIndex(code[:idx[1]], "{"); bracePos >= 0 {
			positions = append(positions, bracePos)
		}
	}
	return positions
}

func findMatchingBrace(s string, startPos int) int {
	if startPos >= len(s) || s[startPos] != '{' {
		return -1
	}
	depth := 0
	for i := startPos; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		case '\'', '"':
			quote := s[i]
			i++
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == quote {
					break
				}
				i++
			}
		case '`':
			i++
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '`' {
					break
				}
				if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
					i += 2
					interpDepth := 1
					for i < len(s) && interpDepth > 0 {
						if s[i] == '{' {
							interpDepth++
						} else if s[i] == '}' {
							interpDepth--
						} else if s[i] == '\\' {
							i++
						}
						if interpDepth > 0 {
							i++
						}
					}
					continue
				}
				i++
			}
		}
	}
	return -1
}

func extractStringsFromParsed(data map[string]interface{}, results *[]ExtractedString, seen map[string]bool, prefix string) {
	for key, val := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}
		switch v := val.(type) {
		case string:
			if (strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "ws://") || strings.HasPrefix(v, "wss://") || strings.HasPrefix(v, "//")) && !seen[v] {
				seen[v] = true
				*results = append(*results, ExtractedString{Value: v, Context: "json_parse_" + fullKey, IsURL: strings.HasPrefix(v, "http") || strings.HasPrefix(v, "//"), IsPath: strings.HasPrefix(v, "/")})
			}
		case map[string]interface{}:
			extractStringsFromParsed(v, results, seen, fullKey)
		case []interface{}:
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					extractStringsFromParsed(m, results, seen, fullKey)
				}
				if s, ok := item.(string); ok {
					if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "/")) && !seen[s] {
						seen[s] = true
						*results = append(*results, ExtractedString{Value: s, Context: "json_parse_" + fullKey + "[]", IsURL: strings.HasPrefix(s, "http"), IsPath: strings.HasPrefix(s, "/")})
					}
				}
			}
		}
	}
}

func extractSvelteKitLoadURLs(code string) []ExtractedString {
	cleaned := stripJSComments(code)
	if !svelteKitLoadPat.MatchString(cleaned) {
		return nil
	}
	var results []ExtractedString
	seen := make(map[string]bool)
	loadSectionRe := regexp.MustCompile(`(?s)(?:export\s+(?:const|function|async\s+function)\s+load\s*[=\(])[\s\S]{0,500}?\}`)
	for _, m := range loadSectionRe.FindAllStringSubmatch(cleaned, -1) {
		if len(m) < 2 {
			continue
		}
		fetchInLoad := regexp.MustCompile(`fetch\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `\)]+)["'\` + "`" + `]`)
		for _, fm := range fetchInLoad.FindAllStringSubmatch(m[0], -1) {
			if len(fm) >= 2 {
				val := strings.TrimSpace(fm[1])
				if !seen[val] && len(val) >= 3 {
					seen[val] = true
					results = append(results, ExtractedString{Value: val, Context: "sveltekit_load_fetch", IsURL: strings.HasPrefix(val, "http"), IsPath: strings.HasPrefix(val, "/")})
				}
			}
		}
	}
	return results
}

func analyzeJS(code string, sourceURL string) JSAnalysisResult {
	var result JSAnalysisResult
	result.Strings = extractAllStrings(code)
	result.ModuleURLs = extractModernJSModuleURLs(code)
	result.TemplateParts = extractTemplateLiteralInterpolations(code)
	result.CSSRefs = extractCSSReferences(code)
	result.EnvURLs = extractEnvironmentURLs(code)
	result.Concatenations = extractConcatenationPatterns(code)
	result.ConfigObjects = extractJSONConfigObjects(code)
	result.SvelteKitURLs = extractSvelteKitLoadURLs(code)
	result.Endpoints = extractEndpoints(code)
	result.Secrets = findSensitive(code, sourceURL)
	return result
}

func extractJSImports(content string) []string {
	var results []string
	seen := make(map[string]bool)
	importPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:import|require)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)?`),
		regexp.MustCompile(`(?:from|import)\s+["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
		regexp.MustCompile(`new\s+(?:Worker|SharedWorker)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
		regexp.MustCompile(`import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
		regexp.MustCompile(`new\s+URL\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
		regexp.MustCompile(`import\.meta\.resolve\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
		regexp.MustCompile(`import\.meta\.glob\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
		regexp.MustCompile(`importScripts\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
		regexp.MustCompile(`require\.resolve\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
		regexp.MustCompile(`require\.context\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
		regexp.MustCompile(`System\.import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
		regexp.MustCompile(`System\.register\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
	}
	for _, re := range importPatterns {
		for _, m := range re.FindAllStringSubmatch(content, -1) {
			if len(m) >= 2 && !seen[m[1]] {
				seen[m[1]] = true
				results = append(results, m[1])
			}
		}
	}
	return results
}
